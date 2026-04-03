# SNEK Reverse

SNEK Reverse is a native Rust reverse engineering workbench with a modern GUI, an analysis pipeline (CFG → IR → SSA), and a scripting + patching workflow designed to stay powerful without feeling like a plane cockpit.

It is built around three ideas:

- Strong foundations (graphs + semantics) so the analysis stays correct as features grow.
- A friendly default layout so you can actually use it day-to-day without hunting through menus.
- Being fucking free.

## Highlights

- Disassembly view with labels/comments/bookmarks and fast navigation
- Control Flow Graph view with interactive node drag + DOT export
- IR + SSA views, plus additional analysis tabs (loops / type inference / alias summary)
- Decompilation output (C/C++ and Rust-style pseudocode)
- Hex view with live patching and hex-dump export
- Python console with presets and workspace scripts
- Global search (Ctrl+F) across all tab exports, plus disassembly-local search (Ctrl+Shift+F)
- SNEK Lab: scientific calculator + custom plotter (expression-based)
- Appearance controls: dark/light + accent color + optional custom palette

## What SNEK Reverse is (and isn't)

SNEK Reverse is a reversing workbench: it loads a binary, analyzes it, and gives you views that let you understand what it does and make controlled edits.

It is not a full debugger (yet), and it does not try to hide the fact that reverse engineering is hard. The goal is to make the core workflow smooth while keeping advanced capabilities available.

## Core pipeline

The analysis pipeline is intentionally compiler-like:

1. Decode instructions
2. Split into basic blocks
3. Build a CFG (successors + predecessors)
4. Lift to a semantic IR
5. Convert to SSA
6. Run optimization / cleanup passes
7. Render IR / SSA views and generate pseudocode

This is what enables features like correct control-flow reasoning, SSA-based transformations, and more stable decompilation output.

## Quick start

### Build

```bash
cargo build --release
```

### Run

```bash
cargo run --release
```

(Or if you're boring just get the latest pre-built exe from the Releases tab)

## Supported formats / architecture notes

Currently the core workflow focuses on PE + x86/x86\_64. The loader and disassembler layers are structured so other formats/architectures can be added without rewriting the GUI.

## Tabs and tools

The app uses a docked/tabbed layout. You can close tabs and reopen them from the View menu.

### Core tabs (default layout)

- Disassembly
- Decompilation (C/C++)
- Decompilation (Rust)
- Hex View
- Graph View
- Functions
- Strings
- Cross References
- Python Console
- Logs
- SNEK Lab

### Advanced tabs (available, but not forced)

- Analysis Data
- IR
- SSA
- Loops
- Types
- Alias
- Imports
- Exports
- Bookmarks
- Symbol Tree
- Registers
- Stack View
- Entropy Graph
- Assets

## UI layout

The default layout is intentionally minimal. Advanced views still exist, but are grouped under:

- View → Advanced Tabs
- View → Reset Layout (Advanced)

This keeps first-glance usability high while keeping the deep tooling one click away.
Layouts are user-facing choices:

- Reset Layout (Simple) keeps daily workflow tight.
- Reset Layout (Advanced) exposes everything for deep dives.

## Navigation & search

- Global Find: Ctrl+F (search across export text from multiple tabs)
- Find in Disassembly: Ctrl+Shift+F (address-based navigation in the listing)
- Find Next / Previous: F3 / Shift+F3
- Back / Forward: Alt+Left / Alt+Right
- Goto Address: Navigate → Goto Address…

Most views have an Export section that turns the current content into selectable text for Ctrl+A / Ctrl+C.

## Disassembly workflow

Disassembly supports:

- Labels
- Comments
- Bookmarks
- Jump-to target
- Cross references

The Export panel is designed for copy/paste into notes or external tooling.

## Graph view

Graph View renders the CFG interactively:

- Zoom + pan
- Drag nodes
- DOT export (copy to clipboard)

## Decompilation

SNEK Reverse generates pseudocode from the lifted IR/SSA pipeline.

Notes:

- The output is designed to be readable and stable, not “perfect C”.
- Type inference is best-effort and improves as more analysis is added.

## IR / SSA / analysis tabs

- IR: semantic view of program operations after lifting
- SSA: renamed variables, phi nodes, and optimized form
- Loops: loop headers/tails and member blocks (natural loop detection)
- Types: best-effort inferred types per SSA variable
- Alias: basic memory location classification and load/store summary

## Hex view & patching

Hex View supports:

- Cursor navigation
- Inline patching (write bytes at cursor)
- Copy line / Copy full hex dump
- Export panel for easy copy/paste

Patches update the in-memory representation used by the views.

## Strings / imports / exports

- Strings view includes quick navigation to cross references when available.
- Imports and exports are extracted from the PE tables (best-effort).

## Python console & scripting workspace

The Python console is a built-in scripting space that can run presets and workspace scripts against the current analysis context.

Use cases:

- Quick triage scripts (indicators, string search, xref reports)
- Automation across functions/blocks
- Custom data extraction

Stdout/stderr are visible and copyable, and certain script outputs can drive UI actions (like goto address / focus xrefs).

## SNEK Lab (calculator + plotter)

Supported:

- Operators: `+ - * / ^` (with unary `-`)
- Variables: `ans`, `x` (plot), constants `pi`, `e`
- Functions: `sin cos tan asin acos atan sqrt abs ln log exp floor ceil round pow min max`

Plot export:

- Copy CSV (x,y)

## Appearance & personalization

- Dark / Light / Custom theme modes
- Accent color (used for selection/link styling)
- Optional custom palette (background/panel/text)
- Simple vs Advanced layout preference

Personalization is saved automatically and restored on next launch.

## Performance notes

SNEK Reverse does analysis work in the background so the GUI stays responsive.

Some heavy views are intentionally “export-driven” (text buffers) so you can search/copy quickly without waiting for complex UI widgets to render thousands of rows.

## Project structure

The repo is split into layers:

- formats: loaders (PE/ELF/Mach-O)
- analysis: disassembly + CFG + IR + SSA + pseudocode
- gui: the workbench UI (tabs, docking, actions, scripts, exports)
- native: optional native helpers via C/C++
- threading: a small thread pool module (separately licensed)

## License

The main project is under the SNEK Reverse Non-Resale License (SR-NR-1.0). You may use, modify, and redistribute freely, but you may not resell the software (original or modified) as a product.

The threading module under `src/threading/` is separately licensed under MIT. See `LICENSE_THREADING`.

## Security / safety notes

Reverse engineering tools handle untrusted inputs. Treat binaries and extracted strings as hostile:

- Do not execute unknown binaries outside a sandbox.
- Be careful when copying/pasting extracted strings into shells.
- Prefer working in VMs for malware.

## Future of the app

So what about the future? Well idk really, I started building this after getting mad at IDA asking me to pay exorbitant sums and Ghidra (which I love and use) feels like a frickin spaceship. P.S I would really appreciate if someone took the time to contribute to the for now very poor documentation of this project, building it took a considerable amount of time and I am kind of in a rush caused by life to release it, with its many incomplete features.

### Long live freeware, **ATroubledSnake**
