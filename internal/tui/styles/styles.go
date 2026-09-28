// Package styles centralizes lipgloss styles used across the TUI so palette
// tweaks happen in one place.
package styles

import "github.com/charmbracelet/lipgloss"

var (
	// Brand palette — muted, terminal-friendly.
	brand  = lipgloss.Color("#f5c93a") // amber
	muted  = lipgloss.Color("#6d7280")
	danger = lipgloss.Color("#ef4444")
	ok     = lipgloss.Color("#10b981")
	warn   = lipgloss.Color("#f59e0b")

	Title = lipgloss.NewStyle().
		Bold(true).
		Foreground(brand)

	Muted = lipgloss.NewStyle().
		Foreground(muted)

	Selected = lipgloss.NewStyle().
			Bold(true).
			Foreground(brand)

	Cursor = lipgloss.NewStyle().
		Bold(true).
		Foreground(brand).
		SetString("➤ ")

	Bullet = lipgloss.NewStyle().SetString("  ")

	Status = map[string]lipgloss.Style{
		"ok":   lipgloss.NewStyle().Foreground(ok).Bold(true),
		"warn": lipgloss.NewStyle().Foreground(warn).Bold(true),
		"fail": lipgloss.NewStyle().Foreground(danger).Bold(true),
	}

	Border = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(muted).
		Padding(0, 1)

	FormLabel = lipgloss.NewStyle().Foreground(muted)
	FormInput = lipgloss.NewStyle().Bold(true)

	Help = lipgloss.NewStyle().Foreground(muted).Italic(true)
)
