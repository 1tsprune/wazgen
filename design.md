# Design — WAZGEN

Locked design system for this app. Tool UI, not marketing pages.

## Genre
modern-minimal (dev tool / SIEM console)

## Macrostructure family
- App pages: Workbench — product surface first, minimal chrome
- Secondary: catalogue panels for patterns + deploy scripts

## Theme (custom · warm gold)
- Paper (dark default): oklch(14% 0.012 70)
- Paper-2: oklch(18% 0.014 70)
- Ink: oklch(94% 0.01 80)
- Ink muted: oklch(68% 0.02 70)
- Rule: oklch(28% 0.02 70)
- Accent: oklch(78% 0.09 75) — 1tsprune gold (~#d4a574)
- Focus: oklch(78% 0.11 75)

## Typography
- Display / UI: Space Grotesk 500–700
- Body: Space Grotesk 400–500
- Mono: JetBrains Mono 400–500
- No italic headers
- No gradient text

## Spacing
4pt named scale in `tokens.css`. Use tokens only.

## Motion
- Easings: --ease-out only for UI
- Reveals: opacity, ≤180ms
- Reduced motion: opacity only ≤150ms

## Microinteractions
- Silent success toast (short, one line)
- Primary CTA filled accent on dark
- Secondary outline only

## CTA voice
- Primary: Generate / Copy rule
- Secondary: Reset / Validate

## What pages MUST share
- Logo, gold accent, Space Grotesk + JetBrains Mono
- 3-surface IA: Workbench · Patterns · Deploy
- History as utility under Workbench, not a marketing page

## What is out of scope / removed from IA
- MITRE map page
- Help as a full nav destination
- AI integration marketing blocks
- Fake Mac window chrome
- Hero badge walls
