package main

import (
	"database/sql"
	"log"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Store provides SQLite-backed persistence for rooms and blacklists.
type Store struct {
	db *sql.DB
	mu sync.Mutex
}

func newStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS rooms (
			key          TEXT PRIMARY KEY,
			name         TEXT NOT NULL,
			password_hash TEXT NOT NULL DEFAULT '',
			created_at   TEXT NOT NULL DEFAULT (datetime('now')),
			bytes_relayed INTEGER NOT NULL DEFAULT 0,
			persistent   INTEGER NOT NULL DEFAULT 1
		);

		CREATE TABLE IF NOT EXISTS blacklist (
			room_key   TEXT NOT NULL,
			client_id  TEXT NOT NULL,
			banned_at  TEXT NOT NULL DEFAULT (datetime('now')),
			PRIMARY KEY (room_key, client_id)
		);

		CREATE INDEX IF NOT EXISTS idx_blacklist_room ON blacklist(room_key);
	`)
	// Migration: add persistent column if not exists (for existing DBs)
	s.db.Exec(`ALTER TABLE rooms ADD COLUMN persistent INTEGER NOT NULL DEFAULT 1`)
	return err
}

// SaveRoom persists a room to SQLite.
func (s *Store) SaveRoom(room *Room) {
	s.mu.Lock()
	defer s.mu.Unlock()

	persistent := 0
	if room.Persistent {
		persistent = 1
	}
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO rooms (key, name, password_hash, created_at, bytes_relayed, persistent) VALUES (?, ?, ?, ?, ?, ?)`,
		room.Key, room.Name, room.PasswordHash,
		room.CreatedAt.UTC().Format(time.RFC3339),
		room.BytesRelayed, persistent,
	)
	if err != nil {
		log.Printf("Store: save room error: %v", err)
	}
}

// DeleteRoom removes a room from SQLite.
func (s *Store) DeleteRoom(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.db.Exec(`DELETE FROM rooms WHERE key = ?`, key)
	s.db.Exec(`DELETE FROM blacklist WHERE room_key = ?`, key)
}

// LoadRooms returns all persisted rooms.
func (s *Store) LoadRooms() []*Room {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`SELECT key, name, password_hash, created_at, bytes_relayed, persistent FROM rooms`)
	if err != nil {
		log.Printf("Store: load rooms error: %v", err)
		return nil
	}
	defer rows.Close()

	var rooms []*Room
	for rows.Next() {
		var key, name, passHash, createdStr string
		var bytesRelayed int64
		var persistent int
		if err := rows.Scan(&key, &name, &passHash, &createdStr, &bytesRelayed, &persistent); err != nil {
			continue
		}
		created, _ := time.Parse(time.RFC3339, createdStr)
		if created.IsZero() {
			created = time.Now()
		}
		room := &Room{
			Name:         name,
			PasswordHash: passHash,
			Key:          key,
			Clients:      make(map[string]*Client),
			Blacklist:    make(map[string]bool),
			BytesRelayed: bytesRelayed,
			CreatedAt:    created,
			Persistent:   persistent == 1,
		}
		rooms = append(rooms, room)
	}

	// Load blacklists
	for _, room := range rooms {
		bRows, err := s.db.Query(`SELECT client_id FROM blacklist WHERE room_key = ?`, room.Key)
		if err != nil {
			continue
		}
		for bRows.Next() {
			var cid string
			if bRows.Scan(&cid) == nil {
				room.Blacklist[cid] = true
			}
		}
		bRows.Close()
	}

	return rooms
}

// SaveBan persists a ban.
func (s *Store) SaveBan(roomKey, clientID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.db.Exec(`INSERT OR IGNORE INTO blacklist (room_key, client_id) VALUES (?, ?)`, roomKey, clientID)
}

// DeleteBan removes a ban.
func (s *Store) DeleteBan(roomKey, clientID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.db.Exec(`DELETE FROM blacklist WHERE room_key = ? AND client_id = ?`, roomKey, clientID)
}

// UpdateBytesRelayed saves the relay byte counter.
func (s *Store) UpdateBytesRelayed(key string, bytes int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.db.Exec(`UPDATE rooms SET bytes_relayed = ? WHERE key = ?`, bytes, key)
}

func (s *Store) Close() {
	if s.db != nil {
		s.db.Close()
	}
}
