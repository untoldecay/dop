# Character system — generation prompt

A reusable brief for an image or design model to create, then iterate on, the
agent characters of the DOP iPhone app. Paste the **System brief** once, then
one **Task** at a time. Keep the **Rules** block in every run; it is what keeps
the family coherent across iterations. References are in
[media/ios-inspiration](media/ios-inspiration/).

---

## System brief

You are designing a family of characters for an iPhone app where each
character is an AI agent the user supervises. Characters are seen at three
sizes: tiny (a 32 pt dot in a swarm), medium (a 110 pt portrait on a decision
card), large (a 220 pt figure on an editor screen). They must read at all
three. They are friendly, physical, and quiet: they never look angry or
pleading, because the user must decide freely. They are not mascots of a
brand; they are a cast.

**Style.** Soft 3D clay. Matte surface with a gentle subsurface glow, one
saturated colour per body, soft top light, a faint contact shadow. No outlines,
no gradients other than the light, no texture. Background plain off-white
(#F7F6F2) unless the task says otherwise. Think of a small vinyl toy
photographed on paper, or the reference images: a yellow rounded triangle
wearing round glasses and a bow tie; a blue cloud in a beret; a purple heart in
sunglasses; a green frog-disc with big round eyes.

**Anatomy.** A body shape from a fixed family, a face made of parts from a
fixed kit, at most two accessories. No arms, no legs, no mouth unless a task
asks for an expression study. The body is the character; the face is small and
placed in the upper middle.

**Rules** (repeat in every run):
1. Body shapes, exactly these and no others: rounded triangle, cloud (five
   lobes), heart, disc, pebble (asymmetric rounded blob), bean. New shapes only
   when a task explicitly adds one.
2. Colours, exactly these: yellow #FFCC00, blue #1E7BFF, purple #B23DD6, green
   #5CC86B, orange #FF8A1F, charcoal #2B2B2B, plus white #F2F2F2 for eyes and
   charcoal for all parts. Never two colours on one body. Never red: red is
   reserved by the app for danger.
3. Eyes: two dots, two ovals, two closed arcs, or two rings. Always a pair,
   always the same kind on both sides. Pupils charcoal; whites only for the
   "ring" kind.
4. Brows: none, flat, raised, slanted-in, slanted-out. Thin charcoal strokes.
5. Accessories, at most two per character, charcoal unless stated: round
   glasses, square glasses, sunglasses, bow tie, beret, cap, tiny crown, scarf.
6. Proportions on a 100-unit body: eyes 10–14 units apart, placed at 40–48
   units from the top; accessories scale to the body, never past its silhouette
   by more than 12 units.
7. Every sheet shows the character on paper, front view, same camera (slight
   high three-quarter, 35 mm feel), same light. Turnarounds add side and back.
8. Each character gets a serial "No. 00N", a one-word name, and a one-line
   trait, set in a small grotesk under the figure, like a specimen card.
9. Silhouette test: in flat black at 32 pt, every body shape must be told
   apart from the others. If two blur together, change the shape, not the face.
10. Nothing on the character may suggest risk, warning, or alarm. No red, no
    exclamation marks, no frowns.

**Derivation rule (for the engineers, keep it visible to the model).** A
character's default is computed from its agent public key: shape = key byte 0
mod 6; colour = byte 1 mod 6; eyes = byte 2 mod 4; brows = byte 3 mod 5;
accessory = byte 4 mod 9 (0 = none); a second accessory only if byte 5 is odd.
Same key, same character, on every device. The editor overrides any field.

---

## Tasks

Run one at a time. Each produces a sheet you can keep, reject, or feed back.

**T1 — The six bodies.** One sheet, six characters, one per body shape, each a
different colour, neutral face (dot eyes, no brows), no accessories. Front
view only. Serials No. 001–006. Goal: approve the shape family.

**T2 — The parts wall.** One sheet laid out like a workshop pegboard: every
eye kind, every brow, every accessory, each shown once in charcoal on paper,
labelled. Goal: approve the kit.

**T3 — Expression study.** Pick one approved body. A 4 × 4 grid: rows are
eye kinds, columns are brow kinds. Same body, same colour, same camera. Goal:
see which combinations read as which mood; mark any that look angry or sad
for removal.

**T4 — Accessory study.** Same body, a 3 × 3 grid of single accessories, then
a row of three with two accessories each. Goal: approve which pairs are
allowed.

**T5 — Three sizes.** Three approved characters, each rendered at 32, 110 and
220 pt on one sheet, true to scale. Goal: confirm readability; anything lost
at 32 pt is simplified.

**T6 — Turnarounds.** The three approved characters, front / side / back,
with the measured spec-sheet treatment: dimension lines, "No. 00N", name,
trait. Goal: the reference sheets the app's renderer will match.

**T7 — The swarm.** Eight to twelve approved characters drifting and
stacking on off-white, some leaning on others, two wearing a small round
badge above the head (charcoal dot, not red). No text. Goal: the Home screen
feel.

**T8 — Derivation check.** Generate six characters from these six fake keys
by applying the derivation rule by hand: `3a 1f 02 04 07 01`, `00 05 03 00 00
00`, `05 02 01 02 03 00`, `02 00 00 01 05 01`, `04 03 02 03 08 00`, `01 04 03 04
02 01`. Goal: confirm the rule yields distinct, pleasant characters without a
human picking.

---

## Iteration loop

After each task, answer in three lines: what is approved, what to change, what
rule to add or tighten. Paste the updated **Rules** block into the next run.
Rules only ever get more specific; never relax one to fit a pretty result.

When a result is good, save the image next to this file under
`media/characters/` with the task id and the serial, and note the seed or the
prompt variant used.

---

## Short prompts for image models

Use with the System brief as context, or standalone when the model has no
system field.

- *Specimen card:* "soft 3D clay character, rounded triangle body, matte
  yellow, two round charcoal glasses, bow tie, two dot eyes, no mouth, no arms,
  on off-white paper, front view, slight high three-quarter camera, soft top
  light, faint contact shadow, specimen card with 'No. 001' and a one-word
  name below, product render, 35 mm, no text other than the label"
- *Parts wall:* "workshop pegboard on off-white, small charcoal character parts
  pinned in a grid: dot eyes, oval eyes, closed eyes, ring eyes, five brow
  shapes, round glasses, square glasses, sunglasses, bow tie, beret, cap, tiny
  crown, scarf, each labelled in small grotesk, flat even light, product
  photography"
- *Swarm:* "ten soft 3D clay characters in six flat colours drifting and
  stacking on off-white paper, cloud, heart, disc, triangle, pebble, bean
  shapes, dot eyes, some wearing berets or glasses, soft light, no text, calm,
  playful, product render"
