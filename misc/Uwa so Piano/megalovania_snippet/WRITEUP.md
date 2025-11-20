# amateursCTF – “Uwa so Piano / megalovania_snippet” Writeup

## Overview

We are given a single file: `megalovania_snippet.mid`, a standard MIDI file with 3 tracks. The goal is to recover the flag hidden somewhere inside this music data.

## Step 1 – Basic inspection

- Checked the file type:
  - `file megalovania_snippet.mid` → Standard MIDI data (format 1) with 3 tracks.
- Ran `strings` to look for an obvious embedded flag:
  - Only standard MIDI markers like `MThd`, `MTrk` appeared, no clear-text flag.

Conclusion: the flag is likely encoded in the MIDI events (notes, timings, velocities, etc.), not as plain text.

## Step 2 – Parsing the MIDI structure

Since the file is a valid MIDI, the easiest way to examine it is via a MIDI parsing library.

- Created a Python virtual environment and installed `mido`:
  - `python3 -m venv venv`
  - `./venv/bin/pip install mido`
- Used a quick Python script to dump the tracks:

```bash
./venv/bin/python - << 'PY'
from mido import MidiFile

mid = MidiFile('megalovania_snippet.mid')
print('ticks_per_beat', mid.ticks_per_beat)
print('tracks', len(mid.tracks))
for i, track in enumerate(mid.tracks):
    print(f'\\n=== Track {i} name: {track.name!r} ===')
    t = 0
    for msg in track:
        t += msg.time
        print(t, msg)
PY
```

Observations:
- Track 0 and Track 2 look like melody/accompaniment (normal notes for Megalovania).
- Track 1 has a pattern of low-pitched notes and suspicious velocity values.

## Step 3 – Spotting the encoding channel

Looking more closely at Track 1, we printed only `note_on`/`note_off` events with non-zero velocity:

```bash
./venv/bin/python - << 'PY'
from mido import MidiFile

mid = MidiFile('megalovania_snippet.mid')
track = mid.tracks[1]
print('len msgs', len(track))
t = 0
for msg in track:
    t += msg.time
    if msg.type == 'note_on' and msg.velocity > 0:
        print(t, msg.note, msg.velocity)
PY
```

Towards the later part of the track, we see a series of low MIDI notes (below ~60) whose velocities cluster around printable ASCII ranges (roughly 32–126). This strongly suggests:

- MIDI `note` field encodes some structural pattern (or is irrelevant).
- MIDI `velocity` field might encode ASCII characters.

## Step 4 – Converting velocities to ASCII

To test the hypothesis, we extracted only the “suspicious” note_on events from Track 1 and converted their velocities to characters when they are printable:

```bash
./venv/bin/python - << 'PY'
from mido import MidiFile

mid = MidiFile('megalovania_snippet.mid')
track = mid.tracks[1]

chars = []
t = 0
print('All sus notes:')
for msg in track:
    t += msg.time
    if msg.type == 'note_on' and msg.velocity > 0 and msg.note < 60:
        c = chr(msg.velocity) if 32 <= msg.velocity <= 126 else '.'
        chars.append(c)
        print(f't={t:5d} note={msg.note:2d} vel={msg.velocity:3d} char={c!r}')

print('\\nString:', ''.join(chars))
PY
```

Output (relevant part):

```text
String: amateursCTF{h1t_th3_n0t3s}amateursCTF{h1t_th3_n0t3s}amateursCTF{h1t_th3_n0t3s}...
```

So Track 1 encodes repeated copies of the same ASCII string in the velocities of low-pitched notes.

## Step 5 – Extracting the flag

From the decoded string, the flag is clearly:

```text
amateursCTF{h1t_th3_n0t3s}
```

This is repeated multiple times, confirming that we decoded it correctly and that the extraction method is robust.

## Final Flag

**Flag:** `amateursCTF{h1t_th3_n0t3s}`

