# BitCraft C# SpacetimeDB Auth Module

A **C# SpacetimeDB 2.3+ server module** implementing the full authentication
and authorisation pipeline for the BitCraft MMORPG server.

It is a faithful port of the Rust auth logic:

| Rust source | C# equivalent |
|---|---|
| `game/src/messages/authentication.rs` | Tables + `Role` enum in `Lib.cs` |
| `game/src/game/handlers/authentication.rs` | `IsAuthenticated`, `HasRole` helpers |
| `global_module/src/game/handlers/authentication.rs` | `Authenticate`, `BlockIdentity` reducers |
| `game/src/lib.rs` (lifecycle) | `OnClientConnected`, `OnClientDisconnected` |
| `game/src/game/handlers/player/sign_in.rs` | `SignIn` reducer |

---

## Project layout

```
csharp_auth_module/
├── BitCraftAuthModule.csproj   <- SpacetimeDB.ServerSDK 2.*
├── README.md
└── Lib.cs                      <- single-file module (canonical STDB 2.x style)
```

---

## SpacetimeDB 2.x API patterns used

All code follows the **canonical SpacetimeDB 2.3+ C# server module** conventions
(identical to the official Blackholio demo):

- Everything lives inside `public static partial class Module { … }`
- Tables are `public partial struct` decorated with `[Table(Accessor = "...", Public = ...)]`
- Field attributes: `[PrimaryKey]`, `[AutoInc]`, `[Unique]`
- BTree indexes: `[SpacetimeDB.Index.BTree(Accessor = "...", Columns = [nameof(field)])]`
- Reducers are `public static void` decorated with `[Reducer]` or `[Reducer(ReducerKind.Init/ClientConnected/ClientDisconnected)]`
- DB access via `ctx.Db.<accessor>.<index>.Find/Filter/Update/Delete/Insert(…)`
- Custom SpacetimeDB types (like `Role` enum) use `[SpacetimeDB.Type]`
- Logging: `Log.Info(…)` / `Log.Warn(…)` / `Log.Error(…)`

---

## Auth pipeline

### Connection (`OnClientConnected`)

```
1. Developer identity?  -> allow (service-account bypass)
2. SkipQueue role?      -> allow (queue bypass)
3. Blocked identity?    -> reject "Unauthorized"
4. Valid auth token?    -> reject "Unauthorized" if missing/expired
5. Already signed in?   -> force sign-out then allow
6. Unknown identity?    -> reject
```

### Sign-in (`SignIn` reducer)

```
1. Resolve UserState
2. Duplicate sign-in guard
3. Queue gate (user.can_sign_in)
4. Mark PlayerState.signed_in = true + insert SignedInPlayerState
```

### Token lifetime

| Context | Lifetime |
|---|---|
| Region module (`IsAuthenticated`) | 24 h |
| Global module (`IsAuthenticatedGlobal`) | 1 h |

### Role hierarchy

```
Player(0) < Partner(1) < SkipQueue(2) < Mod(3) < Gm(4) < Admin(5) < Relay(6)
```

`HasRole(ctx, id, Role.Admin)` returns `true` for `Admin` **and** `Relay`.

---

## Building

```bash
dotnet build BitCraftAuthModule.csproj
```

> **Note:** Do not publish to SpacetimeDB until the module has been reviewed
> and the production `Config.env` value has been changed from `"dev"` to `"prod"`.
