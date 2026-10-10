# DOP for iPhone — design PRD

Status: draft for design, 2026-10-10. Companion to [08-phone-approver.md](08-phone-approver.md),
which holds the trust model and the relay protocol. This document is for the
designer: what the app is, every view, every component, how it moves, and what
"done" looks like. Tracked by bd epic dop-cd4.

## Problem Statement

I run agents on several machines. When one of them needs my yes — to bind a
new bearer, to print keys into a transcript, to use a protected grant — the
question is shown as a QR code in the agent's terminal and dies after five
minutes unless the agent relays it. I type a passphrase into a web page served
by the agent's machine, the one page a fake could imitate. Every question looks
the same whether it is routine or dangerous. And when I want to know what an
agent can reach, or trim its access, I have to be at my Mac in the TUI.

## Solution

A native iPhone app where my agents live as characters. It wakes me when one
of them needs a decision, shows me who asks, from where, and what happens if
I say yes, and lets me answer with Face ID (or the passphrase typed on the
phone). From the same place I can look at any agent, see its bearer, its
grants and the services behind them, add or remove a grant, re-issue or revoke,
and reach everything the TUI offers through a menu of the same shape. It is
calm for the routine, loud for the dangerous, and a little alive all the time.

## User Stories

### Waking and deciding
1. As an operator, I want my phone to buzz when an agent needs a decision, so that requests stop dying in a terminal I am not watching.
2. As an operator, I want the notification itself to say who asks and what kind of request it is, so that I can ignore the routine without opening the app.
3. As an operator, I want to open a request from the notification straight into its card, so that a routine claim is one glance and one Face ID.
4. As an operator, I want the card to lead with the effect in plain words ("wants to print keys into an AI transcript"), so that I never approve something dangerous by reflex.
5. As an operator, I want the dangerous kinds (print keys, print bearer) to look and feel different from a claim, so that my hands slow down when they should.
6. As an operator, I want to see who asks (character, name), from where (host, harness), what it touches (service, grant), and the context when it exists (goal, branch, project), so that I understand the request without leaving the card.
7. As an operator, I want to approve with Face ID, so that I never type a passphrase on a page I cannot trust.
8. As an operator, I want to type the approval passphrase on the phone instead, so that I can still answer when Face ID is unavailable (mask, dark, someone else's phone grip).
9. As an operator, I want rejecting to feel decisive and satisfying, so that I am not shy about saying no.
10. As an operator, I want to see several pending requests as a stack and deal with them one by one, so that a burst from a CI run is not overwhelming.
11. As an operator, I want a request that expired or was answered elsewhere (web page, Mac) to leave the stack on its own, so that I never act on a stale question.
12. As an operator, I want a history of decisions with who decided and how (phone, Mac, web), so that I can audit what happened while I was away.
13. As an operator, I want remote claims staged from a server to appear in the same inbox as local ones, so that I have one place for every question.

### Agents as characters
14. As an operator, I want every agent to have a face from the moment it is claimed, derived from its key, so that I recognise agents at a glance and no two share a face by accident.
15. As an operator, I want an agent that offers its own card (name, avatar, traits) to show it to me once for approval, so that a face I come to trust was chosen by me.
16. As an operator, I want an editor to change an agent's face, colour, name and traits, so that my agents feel like mine.
17. As an operator, I want my agents to be visible together on the home screen as a small swarm, so that opening the app feels like checking on a team, not opening a form.
18. As an operator, I want the swarm to reflect real activity when it can (an agent that just used Notion shows a bubble), so that it tells the truth rather than loops a canned animation.
19. As an operator, I want the agent that needs a decision to move from the swarm into its request card without a cut, so that I keep the thread of who is asking.
20. As an operator, I want the swarm to feel alive with one agent and still readable with twenty, so that the app works on day one and at scale.
21. As an operator, I want an agent that is revoked or expired to leave the swarm with a visible farewell, so that the state change is felt, not just logged.

### Looking at an agent
22. As an operator, I want to tap an agent and see its bearer: subject, status, expiry, binding kind and key type, host it was claimed on, portable or not, who issued it, so that I know what this identity is.
23. As an operator, I want to see the grants on its bearer and, behind each grant, the integration and credential it maps to, so that I can see what the agent can reach in one place.
24. As an operator, I want to add a grant to an agent's bearer from a picker of the vault's grants, so that I can widen access without going to the Mac.
25. As an operator, I want to remove a grant from an agent's bearer, so that I can narrow access the moment I notice it is too wide.
26. As an operator, I want to be told when a grant edit needs the agent to re-claim (ed25519 binding) versus applies live (P-256), so that I know what to expect on the agent side.
27. As an operator, I want to re-issue a bearer (rotate in place, new claim, new PIN) from the agent's page, so that a leaked bearer is replaced from wherever I am.
28. As an operator, I want to revoke an agent with a confirmation that names what breaks, so that revocation is deliberate and reversible only by re-issuing.
29. As an operator, I want to see an agent's recent activity (exec per service, approvals, denials), so that I can judge whether its behaviour matches its goal.
30. As an operator, I want the pending request for an agent to be reachable from the agent's page too, so that context and decision are never two taps apart.

### Managing the vault
31. As an operator, I want a menu with the same shape as the TUI (Add, Issue, List, Remove, Vault, More), so that what I learned on the Mac transfers.
32. As an operator, I want to issue a bearer from the phone (subject, grants, expiry, portable, runs on) and get the handoff text to share, so that onboarding a new agent does not need the Mac open.
33. As an operator, I want to list integrations and their credentials, grants, bearers and team, so that the phone is a complete window on the vault.
34. As an operator, I want to add or edit an integration's description, projects and tags and a grant's prefix, projects and tags, so that routine bookkeeping is a phone task.
35. As an operator, I want to remove a grant or an integration with a clear statement of which bearers are affected, so that I do not break an agent by accident.
36. As an operator, I want team: members, devices, pending invites, with approve and delete, so that onboarding a second admin or another phone happens where the notification arrives.
37. As an operator, I want vault status, sync and doctor results, so that I can tell at a glance whether my machines agree.
38. As an operator, I want settings: my paired phone, notification preferences per request kind, passphrase-on-phone on or off, so that the app behaves the way I want.
39. As an operator, I want operations that need the admin key to be executed by my Mac on my signed instruction, with clear feedback when the Mac is offline, so that I understand why something is queued rather than done.

### Pairing and safety
40. As an operator, I want to pair the phone by scanning a QR from the TUI, so that setup is one scan.
41. As an operator, I want pairing to be approved on the Mac like any device invite, so that a stolen QR alone pairs nothing.
42. As an operator, I want to unpair or remote-wipe a lost phone from the Mac, so that its signatures stop counting immediately.
43. As an operator, I want the app to never hold the admin key, a bearer, or a credential value, so that losing the phone is an inconvenience, not a breach.
44. As an operator, I want the app to tell me plainly when the relay is unreachable and that the Mac passphrase path still works, so that an outage never traps a request.

## Views

### V1 — Home: the swarm
The first screen. Agents as characters drifting in a bounded space; density scales with count (one agent sits centre and breathes; twenty cluster and buzz). Pending requests surface as a badge on the agent and a count at the top. Activity bubbles (stretch) float above an agent briefly when it uses a service. Tap an agent → V3. Tap the inbox count → V2. Bottom bar: Agents, Inbox, Services, Team, More.

Components: `AgentAvatar` (deterministic face from key, or card image, or edited face), `Swarm` (layout, drift, density rules, reduced-motion fallback), `ActivityBubble`, `InboxBadge`.

### V2 — Inbox: pending and history
A stack of request cards, newest on top, dangerous kinds pinned above routine ones. Below the fold, history grouped by day. Each history row: avatar, effect, decision, who decided, how.

Components: `RequestCard` (compact), `DecisionRow`, `KindTag`.

### V3 — Agent page
Header: avatar large, name, host, harness, status. Sections as collapsible cards: Bearer (facts), Grants (each row expands to the integration and credential behind it), Activity, Danger zone (re-issue, revoke). Pending request for this agent, if any, sits at the top as a card and opens V4 with the avatar staying in place.

Components: `AgentHeader`, `BearerFacts`, `GrantRow`, `IntegrationPeek`, `ActivityList`, `DangerZone`.

### V4 — Request card (full)
The decision view. Top: the effect sentence, colour and icon by kind. Middle: avatar with name, then where from, then what it touches, then a folded context block (goal, branch, project, generation). Bottom: Approve (Face ID) and Reject. A small "type passphrase instead" affordance. Expiry countdown is visible but quiet.

Kinds and their mood: claim (neutral), remote claim (neutral, host emphasised), protected grant (amber), print bearer (red), print keys (red, strongest, "keys will be shown in an AI transcript").

Components: `EffectHeadline`, `ContextBlock`, `ApproveButton` (label morphs Approve → Approving → Approved), `RejectButton`, `PassphraseSheet`, `ExpiryRing`.

### V5 — Character editor
Opened from V3 header. Shape, eyes, brows, colour, accessory; name and traits. Live preview on the same avatar instance that will travel back to the swarm. "Offered by the agent" card shown here for accept / replace when one exists.

Components: `FaceCanvas`, `TraitChips`, `OfferedCard`.

### V6 — Grant picker
From V3 Grants › Add. The vault's grants grouped by integration, with the ones already on the bearer marked. Protected grants ask the approval passphrase (sheet). Confirm shows the new grant set and whether it applies live or needs a re-claim.

Components: `GrantPicker`, `PassphraseSheet`, `ChangeSummary`.

### V7 — Issue bearer
Mirrors the TUI wizard as trays: subject → grants → expiry → portable → runs on → review → shown-once handoff with a share button. The handoff is shown once; leaving needs a second confirmation.

Components: `Tray` stack, `OnceScreen`, `ShareHandoff`.

### V8 — Services
Integrations list → integration page (kind, credentials, projects, tags, description, the grants that use it, the bearers behind those grants). Edit metadata in trays. Remove with affected-bearers statement.

### V9 — Team
Members, devices (phones included), pending invites with approve / delete. Pair another phone from here.

### V10 — Vault and More
Status, sync, doctor as a read view with one action each. Settings: notifications per kind, passphrase-on-phone, this device, unpair.

## Motion and continuity principles

Adopted from Benji Taylor's "Family values" and adapted:

- **Persistence.** A component that will exist in the next screen stays the same component. The agent avatar is the primary persistent element: swarm → agent page → request card → editor, always the same instance moving, never a cut. Grant rows persist from the agent page into the picker.
- **Fly, don't teleport.** Every transition explains the route from A to B. Tab changes move in the direction of the tab. Trays rise over the current screen so context stays visible; full-screen pushes are reserved for the request card, which deserves the whole stage.
- **Trays for depth.** Multi-step flows (issue bearer, grant picker, passphrase) are successive trays of different heights so progress is read from the silhouette.
- **Text morphs for action.** Approve → Approving → Approved shares letters; Reject does the same. The headline of a request never changes wholesale under the finger.
- **Delight-impact curve.** Frequent actions (approve a claim) get small, quick, consistent feedback. Rare actions (revoke, unpair, first pairing, an agent's farewell) earn the big moments. Never repeat a big moment on a frequent action.
- **Uniform polish.** The settings screen and the doctor view get the same care as the swarm, or the whole app reads as unfinished.
- **Truthful motion.** The swarm shows real state. No fake busyness. Reduced Motion is honoured: drift becomes still, transitions become fades, nothing is lost.
- **Speed budget.** A routine claim from notification to approved is under three seconds of the user's attention: no intro animation stands between the tap and the card.

## Implementation Decisions

- **Two planes.** Decisions (approve, reject) are signed on the phone and verified by the requester; they need no Mac. Management (grants, issue, revoke, integrations, team) are signed commands the admin Mac executes through its daemon; the phone shows "queued for your Mac" when it is offline. The design must make the plane visible without making it a lesson.
- **Identity.** The phone is a paired device with a Secure Enclave key, recorded in the vault and approved like any device. Avatars are labels on identities, never identities.
- **Agent card.** A small, agent-declared card (name, image or shape spec, traits) stored on the binding at claim or later via exec; shown once to the operator before it is used; operator edits override and are signed by the operator.
- **Default face.** A deterministic face derived from the agent public key, rendered by the app; the same key gives the same face on every device.
- **Request content** reaches the phone sealed to its key through the relay on Cloudron; the phone never runs git. Activity ticks, when present, carry subject and service name only.
- **Approval kinds** are a closed set: claim, remote-claim, protected-grant, print-bearer, print-keys. Mood, colour and copy are defined per kind once and shared with the web page.
- **Context fields** on a request: subject, agent name, host, harness, kind, effect, service, grant, expiry, and optional goal, branch, project, generation. Goal and project are declared by the agent (future exec flag, separate conversation); branch and working directory are read by dop when present.
- **Native SwiftUI**, shared-element transitions for the avatar, trays as a reusable container, haptics paired with each decision state.

## Testing Decisions

- Protocol and relay are tested on the dop side (e2e scripts in the existing style, a second Mac as the first "device") before any app code; the app is never the only test of the signing path.
- App: snapshot tests of each view in light/dark and Reduced Motion; a scripted walk of the five request kinds; a deterministic-face test (same key → same face, different keys → different faces, across app versions).
- Good test: external behaviour only. The swarm is tested for layout rules (density bands, readable at one and at twenty), not for pixel positions.

## Out of Scope

- 3D avatars, avatar generation from a photo.
- Unlocking the Mac admin session from the phone, any handling of the admin passphrase on the phone.
- Credential values ever displayed on the phone.
- Traffic monitoring, threat scoring, goal declaration on exec (future work, separate conversation; this design leaves room for a per-agent activity view and a context block).
- Android.

## Further Notes

- Motion and micro-interaction references from Camille are to follow and should be folded into the principles section.
- The same per-kind presentation rules should be ported back to the web approval page so both surfaces agree (dop-dkj).
- Phasing: the swarm, inbox, request card and agent page (read-only) are the prototype; grant add/remove and revoke are the first management commands; issue and the full menu follow.
