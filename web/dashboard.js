'use strict';

class Dashboard {
    constructor() {
        this.pollInterval = 3000;
        this.timer = null;
        this.token = null;
        this.searchQuery = '';
        this.peerFirstSeen = {};
        this.lastStats = null;
        this.activeTab = 'rooms';
        this.init();
    }

    init() {
        // Bind login
        document.getElementById('login-btn').addEventListener('click', () => this.login());
        document.getElementById('login-password').addEventListener('keydown', e => {
            if (e.key === 'Enter') this.login();
        });

        // Bind create room
        document.getElementById('create-room-btn').addEventListener('click', () => this.createRoom());
        document.getElementById('new-room-name').addEventListener('keydown', e => {
            if (e.key === 'Enter') this.createRoom();
        });

        // Bind logout
        document.getElementById('logout-btn').addEventListener('click', () => this.logout());

        // Bind search
        document.getElementById('search-input').addEventListener('input', e => {
            this.searchQuery = e.target.value.trim().toLowerCase();
            if (this.lastStats) {
                this.render(this.lastStats.rooms || []);
            }
        });

        // Check existing session
        this.checkSession();
    }

    async checkSession() {
        try {
            const resp = await fetch('/api/auth');
            if (resp.ok) {
                this.showDashboard();
                return;
            }
        } catch {}
        this.showLogin();
    }

    async login() {
        const input = document.getElementById('login-password');
        const errEl = document.getElementById('login-error');
        const password = input.value.trim();
        errEl.textContent = '';

        if (!password) { input.focus(); return; }

        try {
            const resp = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password }),
            });

            if (!resp.ok) {
                errEl.textContent = 'Invalid password';
                input.value = '';
                input.focus();
                return;
            }

            const data = await resp.json();
            this.token = data.token;
            this.showDashboard();
        } catch (err) {
            errEl.textContent = 'Connection failed';
        }
    }

    logout() {
        document.cookie = 'stun_max_token=; Max-Age=0; path=/';
        this.token = null;
        if (this.timer) clearInterval(this.timer);
        this.showLogin();
    }

    showLogin() {
        document.getElementById('login-page').style.display = 'flex';
        document.getElementById('dashboard-page').style.display = 'none';
        document.getElementById('login-password').value = '';
        document.getElementById('login-error').textContent = '';
        document.getElementById('login-password').focus();
    }

    showDashboard() {
        document.getElementById('login-page').style.display = 'none';
        document.getElementById('dashboard-page').style.display = 'block';
        this.refresh();
        if (this.timer) clearInterval(this.timer);
        this.timer = setInterval(() => this.refresh(), this.pollInterval);
    }

    async apiFetch(url, opts = {}) {
        const resp = await fetch(url, opts);
        if (resp.status === 401) {
            this.logout();
            return null;
        }
        return resp;
    }

    async refresh() {
        try {
            const resp = await this.apiFetch('/api/stats');
            if (!resp) return;
            if (!resp.ok) {
                this.setStatus('error', `HTTP ${resp.status}`);
                return;
            }
            const stats = await resp.json();
            this.lastStats = stats;

            document.getElementById('room-count').textContent = stats.total_rooms;
            document.getElementById('peer-count').textContent = stats.total_peers;
            document.getElementById('uptime-value').textContent = stats.uptime || '-';
            document.getElementById('bytes-relayed-value').textContent = this.formatBytes(stats.total_bytes_relayed || 0);
            document.getElementById('active-connections').textContent = stats.active_connections || 0;
            document.getElementById('server-uptime').textContent = stats.uptime || '-';

            this.trackPeers(stats.rooms || []);
            this.render(stats.rooms || []);
            this.setStatus('online', 'Connected');
            this.updateLastRefresh();
            if (this.activeTab === 'stun') this.refreshStun();
        } catch {
            this.setStatus('error', 'Offline');
        }
    }

    updateLastRefresh() {
        const el = document.getElementById('last-refresh');
        const now = new Date();
        const hh = String(now.getHours()).padStart(2, '0');
        const mm = String(now.getMinutes()).padStart(2, '0');
        const ss = String(now.getSeconds()).padStart(2, '0');
        el.textContent = `Last refresh: ${hh}:${mm}:${ss}`;
    }

    trackPeers(rooms) {
        const now = Date.now();
        const currentIds = new Set();
        for (const room of rooms) {
            for (const p of room.peers) {
                const key = room.name + '::' + p.id;
                currentIds.add(key);
                if (!this.peerFirstSeen[key]) {
                    this.peerFirstSeen[key] = now;
                }
            }
        }
        // Clean up peers that left
        for (const key of Object.keys(this.peerFirstSeen)) {
            if (!currentIds.has(key)) {
                delete this.peerFirstSeen[key];
            }
        }
    }

    getPeerDuration(roomName, peerId) {
        const key = roomName + '::' + peerId;
        const first = this.peerFirstSeen[key];
        if (!first) return '';
        const mins = Math.floor((Date.now() - first) / 60000);
        if (mins < 1) return 'just now';
        if (mins < 60) return `${mins}m ago`;
        const hours = Math.floor(mins / 60);
        const remMins = mins % 60;
        return `${hours}h${remMins}m ago`;
    }

    setStatus(state, text) {
        const dot = document.getElementById('status-dot');
        const label = document.getElementById('status-text');
        dot.style.background = state === 'online' ? '#00c853' : '#ff4444';
        label.textContent = text;
    }

    async createRoom() {
        const nameEl = document.getElementById('new-room-name');
        const passEl = document.getElementById('new-room-pass');
        const name = nameEl.value.trim();
        if (!name) { nameEl.focus(); return; }

        try {
            const resp = await this.apiFetch('/api/rooms', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, password: passEl.value }),
            });
            if (resp && resp.ok) {
                nameEl.value = '';
                passEl.value = '';
                this.refresh();
            }
        } catch {}
    }

    async deleteRoom(name) {
        if (!confirm(`Delete room "${name}" and disconnect all peers?`)) return;
        try {
            await this.apiFetch(`/api/rooms?name=${encodeURIComponent(name)}`, { method: 'DELETE' });
            this.refresh();
        } catch {}
    }

    async toggleLock(room, locked) {
        try {
            await this.apiFetch('/api/rooms/lock', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ room, locked }),
            });
            this.refresh();
        } catch {}
    }

    async toggleRelay(room, disabled) {
        try {
            await this.apiFetch('/api/relay', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ room, disabled }),
            });
            this.refresh();
        } catch {}
    }

    async toggleGlobalRelay(disabled) {
        try {
            await this.apiFetch('/api/relay', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ room: '', disabled }),
            });
            this.refresh();
        } catch {}
    }

    async kickClient(room, clientId) {
        if (!confirm(`Kick client ${clientId} from room "${room}"?`)) return;
        try {
            await this.apiFetch('/api/rooms/kick', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ room, client_id: clientId }),
            });
            this.refresh();
        } catch {}
    }

    async banClient(room, clientId) {
        if (!confirm(`Ban client ${clientId} from room "${room}"?`)) return;
        try {
            await this.apiFetch('/api/rooms/ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ room, client_id: clientId }),
            });
            this.refresh();
        } catch {}
    }

    async unbanClient(room, clientId) {
        try {
            await this.apiFetch('/api/rooms/unban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ room, client_id: clientId }),
            });
            this.refresh();
        } catch {}
    }

    switchTab(tab) {
        this.activeTab = tab;
        document.querySelectorAll('.tab-btn').forEach(b => {
            b.classList.toggle('tab-active', b.dataset.tab === tab);
        });
        document.querySelectorAll('[data-tab-content]').forEach(el => {
            el.style.display = el.dataset.tabContent === tab ? '' : 'none';
        });
        if (tab === 'stun') this.refreshStun();
    }

    async refreshStun() {
        try {
            const resp = await this.apiFetch('/api/stun');
            if (!resp || !resp.ok) {
                document.getElementById('stun-clients-list').innerHTML = '';
                document.getElementById('no-stun-clients').style.display = 'block';
                document.getElementById('no-stun-clients').textContent = 'STUN server unreachable';
                return;
            }
            const data = await resp.json();
            document.getElementById('stun-requests').textContent = this.formatNumber(data.total_requests || 0);
            document.getElementById('stun-clients').textContent = data.unique_clients || 0;
            document.getElementById('stun-errors').textContent = data.total_errors || 0;
            document.getElementById('stun-uptime').textContent = data.uptime || '-';
            this.renderStunClients(data.recent_clients || []);
        } catch {
            document.getElementById('no-stun-clients').style.display = 'block';
            document.getElementById('no-stun-clients').textContent = 'Failed to load STUN stats';
        }
    }

    renderStunClients(clients) {
        const container = document.getElementById('stun-clients-list');
        const noClients = document.getElementById('no-stun-clients');

        if (clients.length === 0) {
            container.innerHTML = '';
            noClients.style.display = 'block';
            return;
        }
        noClients.style.display = 'none';

        container.innerHTML = `
            <table class="peer-table">
                <thead><tr>
                    <th>Client IP</th>
                    <th>Public Address</th>
                    <th>Requests</th>
                    <th>First Seen</th>
                    <th>Last Seen</th>
                </tr></thead>
                <tbody>
                    ${clients.map(c => `
                        <tr>
                            <td class="peer-id">${this.esc(c.ip)}</td>
                            <td class="peer-endpoint">${this.esc(c.public_addr)}</td>
                            <td><span class="mode-badge mode-direct">${c.requests}</span></td>
                            <td class="peer-duration">${this.formatTime(c.first_seen)}</td>
                            <td class="peer-duration">${this.formatTime(c.last_seen)}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    }

    formatNumber(n) {
        if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
        if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
        return String(n);
    }

    formatTime(isoStr) {
        if (!isoStr) return '-';
        const d = new Date(isoStr);
        if (isNaN(d.getTime())) return '-';
        const now = Date.now();
        const diff = Math.floor((now - d.getTime()) / 1000);
        if (diff < 60) return 'just now';
        if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
        if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
        return d.toLocaleDateString();
    }

    filterRooms(rooms) {
        if (!this.searchQuery) return rooms;
        return rooms.filter(room => {
            if (room.name.toLowerCase().includes(this.searchQuery)) return true;
            for (const p of room.peers) {
                if ((p.name || '').toLowerCase().includes(this.searchQuery)) return true;
                if (p.id.toLowerCase().includes(this.searchQuery)) return true;
            }
            return false;
        });
    }

    render(rooms) {
        let directCount = 0, relayCount = 0;
        for (const room of rooms) {
            for (const p of room.peers) {
                if (p.status === 'direct') directCount++;
                if (p.status === 'relay') relayCount++;
            }
        }

        document.getElementById('direct-count').textContent = directCount;
        document.getElementById('relay-count').textContent = relayCount;

        const filtered = this.filterRooms(rooms);
        const container = document.getElementById('rooms-list');
        const noRooms = document.getElementById('no-rooms');

        if (filtered.length === 0) {
            container.innerHTML = '';
            noRooms.style.display = 'block';
            noRooms.textContent = this.searchQuery ? 'No matching rooms or peers' : 'No active rooms';
            return;
        }
        noRooms.style.display = 'none';

        container.innerHTML = filtered.map(room => `
            <div class="room-card">
                <div class="room-header">
                    <span class="room-name">${this.esc(room.name)}</span>
                    <span class="room-badge ${room.protected ? 'badge-protected' : 'badge-open'}">
                        ${room.protected ? 'Protected' : 'Open'}
                    </span>
                    <span class="room-badge ${room.persistent ? 'badge-persistent' : 'badge-temp'}">
                        ${room.persistent ? 'Persistent' : (room.owner_name ? 'Owner: ' + this.esc(room.owner_name) : 'Temp')}
                    </span>
                    <span class="room-traffic">${this.formatBytes(room.bytes_relayed || 0)} relayed</span>
                    ${room.created_at ? `<span class="room-created">${this.formatCreatedAt(room.created_at)}</span>` : ''}
                    <span class="room-peer-count">${room.peers.length} peer${room.peers.length !== 1 ? 's' : ''}</span>
                    <button class="lock-toggle ${room.locked ? 'lock-on' : 'lock-off'}" onclick="app.toggleLock('${this.esc(room.name)}', ${!room.locked})">${room.locked ? '🔒 Locked' : '🔓 Open'}</button>
                    <button class="relay-toggle ${room.relay_disabled ? 'relay-off' : 'relay-on'}" onclick="app.toggleRelay('${this.esc(room.name)}', ${!room.relay_disabled})">${room.relay_disabled ? '🚫 Relay Off' : '✓ Relay On'}</button>
                    <button class="room-delete" onclick="app.deleteRoom('${this.esc(room.name)}')">Delete</button>
                </div>
                ${room.peers.length > 0 ? `
                <table class="peer-table">
                    <thead><tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>Connection</th>
                        <th>NAT Type</th>
                        <th>Features</th>
                        <th>Endpoint</th>
                        <th>Location</th>
                        <th>Duration</th>
                        <th></th>
                    </tr></thead>
                    <tbody>
                        ${room.peers.map(p => `
                            <tr>
                                <td class="peer-id">${this.esc(p.id)}</td>
                                <td class="peer-name-cell">
                                    ${this.esc(p.name || '-')}
                                    ${p.nat_type ? this.renderNatBadge(p.nat_type) : ''}
                                </td>
                                <td><span class="mode-badge mode-${p.status}">
                                    ${p.status === 'direct' ? 'P2P' : p.status === 'relay' ? 'RELAY' : '...'}
                                </span></td>
                                <td>${p.nat_type ? this.renderNatBadgeColumn(p.nat_type) : '<span style="color:#666">-</span>'}</td>
                                <td class="peer-features">${this.renderFeatures(p.features)}</td>
                                <td class="peer-endpoint">${this.esc(p.endpoint || '-')}</td>
                                <td class="peer-location">${this.renderIPInfo(p.ip_info)}</td>
                                <td class="peer-duration">${this.getPeerDuration(room.name, p.id)}</td>
                                <td class="peer-actions">
                                    <button class="peer-kick-btn" onclick="app.kickClient('${this.esc(room.name)}','${this.esc(p.id)}')">Kick</button>
                                    <button class="peer-ban-btn" onclick="app.banClient('${this.esc(room.name)}','${this.esc(p.id)}')">Ban</button>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>` : '<div class="empty-state" style="padding:20px">No peers connected</div>'}
                ${room.blacklist && room.blacklist.length > 0 ? `
                <div class="banned-section">
                    <div class="banned-title">Banned (${room.blacklist.length})</div>
                    <div class="banned-list">
                        ${room.blacklist.map(id => `
                            <span class="banned-entry">
                                <span class="banned-id">${this.esc(id)}</span>
                                <button class="peer-unban-btn" onclick="app.unbanClient('${this.esc(room.name)}','${this.esc(id)}')">Unban</button>
                            </span>
                        `).join('')}
                    </div>
                </div>` : ''}
            </div>
        `).join('');
    }

    getNatLevel(natType) {
        if (!natType) return 0;
        const upper = natType.toUpperCase();
        if (upper.includes('1') || upper === 'FULL CONE') return 1;
        if (upper.includes('2') || upper === 'RESTRICTED CONE') return 2;
        if (upper.includes('3') || upper === 'PORT RESTRICTED') return 3;
        if (upper.includes('4') || upper === 'SYMMETRIC') return 4;
        return 0;
    }

    renderNatBadge(natType) {
        const level = this.getNatLevel(natType);
        if (level === 0) return '';
        return ` <span class="nat-badge nat-${level}" title="${this.esc(natType)}">${this.esc(natType)}</span>`;
    }

    renderNatBadgeColumn(natType) {
        const level = this.getNatLevel(natType);
        if (level === 0) return `<span style="color:#666">${this.esc(natType)}</span>`;
        return `<span class="nat-badge nat-${level}">${this.esc(natType)}</span>`;
    }

    formatCreatedAt(isoStr) {
        try {
            const d = new Date(isoStr);
            const now = new Date();
            const diffMs = now - d;
            const diffMins = Math.floor(diffMs / 60000);
            if (diffMins < 1) return 'Created just now';
            if (diffMins < 60) return `Created ${diffMins}m ago`;
            const diffHours = Math.floor(diffMins / 60);
            if (diffHours < 24) return `Created ${diffHours}h ago`;
            const diffDays = Math.floor(diffHours / 24);
            return `Created ${diffDays}d ago`;
        } catch {
            return '';
        }
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    esc(str) {
        const d = document.createElement('div');
        d.textContent = str;
        return d.innerHTML;
    }

    renderIPInfo(info) {
        if (!info || !info.country) return '<span style="color:#555">-</span>';
        const summary = info.summary || info.country || '-';
        const isp = info.isp || '';
        const title = [info.country, info.region, info.city, isp].filter(Boolean).join(' | ');
        let display = this.esc(info.city || info.region || info.country);
        if (isp) display += ` <span class="ip-asn">${this.esc(isp)}</span>`;
        return `<span class="ip-location" title="${this.esc(title)}">${display}</span>`;
    }

    renderFeatures(features) {
        if (!features || Object.keys(features).length === 0) return '<span style="color:#666">-</span>';
        const badges = [];
        if (features.vpn) badges.push(`<span class="feature-badge feature-vpn" title="VPN with ${this.esc(features.vpn)}">VPN</span>`);
        if (features.forwards) badges.push(`<span class="feature-badge feature-fwd" title="${features.forwards} active forwards">${this.esc(features.forwards)} fwd</span>`);
        if (features.vpn_routes) badges.push(`<span class="feature-badge feature-route" title="Routes: ${this.esc(features.vpn_routes)}">routes</span>`);
        return badges.join(' ') || '<span style="color:#666">-</span>';
    }
}

const app = new Dashboard();
