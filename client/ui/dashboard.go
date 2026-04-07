package ui

import (
	"image"
	"image/color"

	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

// Tab identifies a dashboard tab.
type Tab int

const (
	TabPeers Tab = iota
	TabForwards
	TabFiles
	TabVPN
	TabSpeedTest
	TabTools
	TabSettings
	TabLogs
)

var tabNames = [8]string{"Peers", "Forwards", "Files", "VPN", "Speed Test", "Tools", "Settings", "Logs"}

// DashboardScreen holds state for the main dashboard.
type DashboardScreen struct {
	ActiveTab     Tab
	TabButtons    [8]widget.Clickable
	DisconnectBtn widget.Clickable
	TabList       widget.List // scrollable tab bar for mobile

	Peers     PeersPanel
	Forwards  ForwardsPanel
	Files     FilesPanel
	VPN       VPNPanel
	SpeedTest SpeedTestPanel
	Tools     ToolsPanel
	Settings  SettingsPanel
	Logs      LogsPanel

	tabInited bool
}

// Layout renders the dashboard screen.
func (d *DashboardScreen) Layout(gtx layout.Context, th *material.Theme, a *App) layout.Dimensions {
	// Handle tab clicks
	for i := range d.TabButtons {
		if d.TabButtons[i].Clicked(gtx) {
			d.ActiveTab = Tab(i)
		}
	}
	// Handle disconnect
	if d.DisconnectBtn.Clicked(gtx) {
		a.DoDisconnect()
		return layout.Dimensions{Size: gtx.Constraints.Max}
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		// Top bar
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return d.layoutTopBar(gtx, th, a)
		}),
		// Tab bar
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return d.layoutTabBar(gtx, th)
		}),
		// Content area
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(16), Right: unit.Dp(16)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				switch d.ActiveTab {
				case TabPeers:
					return d.Peers.Layout(gtx, th, a)
				case TabForwards:
					return d.Forwards.Layout(gtx, th, a)
				case TabFiles:
					return d.Files.Layout(gtx, th, a)
				case TabVPN:
					return d.VPN.Layout(gtx, th, a)
				case TabSpeedTest:
					return d.SpeedTest.Layout(gtx, th, a)
				case TabTools:
					return d.Tools.Layout(gtx, th, a)
				case TabSettings:
					return d.Settings.Layout(gtx, th, a)
				case TabLogs:
					return d.Logs.Layout(gtx, th, a)
				}
				return layout.Dimensions{Size: gtx.Constraints.Max}
			})
		}),
	)
}

func (d *DashboardScreen) layoutTopBar(gtx layout.Context, th *material.Theme, a *App) layout.Dimensions {
	return layout.Stack{}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			paint.FillShape(gtx.Ops, CardColor, clip.Rect{Max: image.Pt(gtx.Constraints.Max.X, gtx.Constraints.Min.Y)}.Op())
			return layout.Dimensions{Size: image.Pt(gtx.Constraints.Max.X, gtx.Constraints.Min.Y)}
		}),
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(8), Right: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Spacing: layout.SpaceBetween, Alignment: layout.Middle}.Layout(gtx,
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								initLogo()
								if logoSize.X == 0 {
									return layout.Dimensions{}
								}
								sz := gtx.Dp(unit.Dp(28))
								gtx.Constraints = layout.Exact(image.Pt(sz, sz))
								img := widget.Image{Src: logoOp, Fit: widget.Contain}
								return img.Layout(gtx)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Left: unit.Dp(6)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									roomText := "Room: " + a.RoomName
									if a.Client != nil && a.Client.RelayDisabled() {
										roomText += " [P2P Only]"
									}
									room := material.Caption(th, roomText)
									if a.Client != nil && a.Client.RelayDisabled() {
										room.Color = WarningColor
									} else {
										room.Color = DimColor
									}
									return room.Layout(gtx)
								})
							}),
						)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						btn := material.Button(th, &d.DisconnectBtn, "Disconnect")
						btn.Background = ErrorColor
						btn.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
						btn.CornerRadius = unit.Dp(4)
						btn.TextSize = unit.Sp(11)
						btn.Inset = layout.Inset{Top: unit.Dp(4), Bottom: unit.Dp(4), Left: unit.Dp(8), Right: unit.Dp(8)}
						return btn.Layout(gtx)
					}),
				)
			})
		}),
	)
}

func (d *DashboardScreen) layoutTabBar(gtx layout.Context, th *material.Theme) layout.Dimensions {
	if !d.tabInited {
		d.tabInited = true
		d.TabList.Axis = layout.Horizontal
	}

	return layout.Stack{}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			// Bottom border
			sz := image.Pt(gtx.Constraints.Max.X, gtx.Constraints.Min.Y)
			paint.FillShape(gtx.Ops, BorderColor, clip.Rect{Max: sz}.Op())
			return layout.Dimensions{Size: sz}
		}),
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Left: unit.Dp(8), Right: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				// Scrollable horizontal tab list without scrollbar indicator
				return d.TabList.Layout(gtx, len(d.TabButtons), func(gtx layout.Context, idx int) layout.Dimensions {
					return d.layoutTab(gtx, th, idx)
				})
			})
		}),
	)
}

func (d *DashboardScreen) layoutTab(gtx layout.Context, th *material.Theme, idx int) layout.Dimensions {
	active := d.ActiveTab == Tab(idx)
	return layout.Stack{Alignment: layout.S}.Layout(gtx,
		layout.Stacked(func(gtx layout.Context) layout.Dimensions {
			return d.TabButtons[idx].Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(6), Right: unit.Dp(6)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					lbl := material.Body2(th, tabNames[idx])
					if active {
						lbl.Color = AccentColor
					} else {
						lbl.Color = DimColor
					}
					lbl.Alignment = text.Middle
					return lbl.Layout(gtx)
				})
			})
		}),
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			if !active {
				return layout.Dimensions{}
			}
			// Active indicator line at bottom
			h := gtx.Dp(unit.Dp(2))
			sz := image.Pt(gtx.Constraints.Min.X, h)
			off := image.Pt(0, gtx.Constraints.Min.Y-h)
			paint.FillShape(gtx.Ops, AccentColor, clip.Rect{Min: off, Max: image.Pt(off.X+sz.X, off.Y+sz.Y)}.Op())
			return layout.Dimensions{Size: image.Pt(gtx.Constraints.Min.X, gtx.Constraints.Min.Y)}
		}),
	)
}
