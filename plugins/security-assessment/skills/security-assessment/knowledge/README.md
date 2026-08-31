# Knowledge Base

Cross-engagement learning. Grown by `sa retro promote`, which blocks on customer identifiers and
requires human approval (`references/retrospective.md`).

| File | Holds |
|---|---|
| `detection-patterns.md` | Where a class of weakness tends to hide, and how to look for it |
| `verification-recipes.md` | How to settle a hypothesis cheaply and conclusively |
| `false-positive-catalog.md` | Patterns that look bad and are not, with the reason |

**Rules**

1. **No customer information, ever.** No names, domains, IPs, repository paths, ARNs, account IDs,
   person names, or ticket references. If an entry only makes sense with a specific customer's
   architecture in mind, it is not general enough to be here — rewrite it or drop it.
2. Every entry: **Pattern → Why it matters → How to check → How to falsify → Common FP cause.**
3. Entries carry hit/miss counts, updated at each engagement. **An entry whose misses exceed its
   hits is a bad entry — fix it or delete it.** A knowledge base that only grows becomes noise.
