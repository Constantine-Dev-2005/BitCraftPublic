// ---------------------------------------------------------------------------
// BitCraft – C# SpacetimeDB 2.3 Authentication / Authorization Module
//
// Mirrors the Rust auth pipeline in:
//   game/src/messages/authentication.rs
//   game/src/game/handlers/authentication.rs
//   global_module/src/game/handlers/authentication.rs
//   game/src/lib.rs                          (lifecycle reducers)
//   game/src/game/handlers/player/sign_in.rs
//
// Build target : .NET 10 / C# 14
// Runtime      : SpacetimeDB 2.3.*  (SpacetimeDB.Runtime NuGet package)
// ---------------------------------------------------------------------------
using SpacetimeDB;   // brings Table, Reducer, PrimaryKey, Unique, Type, Index,
                     // Identity, ReducerContext, Log, … into scope

public static partial class Module
{
    // ======================================================================
    //  Custom SpacetimeDB type
    // ======================================================================

    /// <summary>
    /// Access-level hierarchy — higher ordinal == more privilege.
    /// Matches the Rust <c>Role</c> enum exactly (repr i32).
    /// </summary>
    [Type]
    public enum Role
    {
        Player    = 0,
        Partner   = 1,
        SkipQueue = 2,
        Mod       = 3,
        Gm        = 4,
        Admin     = 5,
        Relay     = 6,
    }

    // ======================================================================
    //  Tables
    // ======================================================================

    // -- Shared tables (global module owns; replicated to all regions) ------

    /// <summary>
    /// Timestamp of the last granted session token.
    /// Token lifetime: 24 h (region modules) / 1 h (global module).
    /// </summary>
    [Table(Accessor = "user_authentication_state", Public = false)]
    public partial struct UserAuthenticationState
    {
        [PrimaryKey]
        public Identity          identity;
        public SpacetimeDB.Timestamp timestamp;
    }

    /// <summary>
    /// Maps every identity to its highest-granted <see cref="Role"/>.
    /// Public so clients can read back their own entry.
    /// </summary>
    [Table(Accessor = "identity_role", Public = true)]
    [Index.BTree(Accessor = "by_identity", Columns = [nameof(IdentityRole.identity)])]
    public partial struct IdentityRole
    {
        [PrimaryKey]
        public Identity identity;
        public Role     role;
    }

    /// <summary>Identities permanently barred from connecting.</summary>
    [Table(Accessor = "blocked_identity", Public = false)]
    public partial struct BlockedIdentity
    {
        [PrimaryKey]
        public Identity identity;
    }

    // -- Private tables ----------------------------------------------------

    /// <summary>
    /// Service-account / bot identities that bypass the auth flow.
    /// <b>Never make this table public</b> — the email column must stay private.
    /// </summary>
    [Table(Accessor = "developer", Public = false)]
    public partial struct Developer
    {
        [PrimaryKey]
        public Identity identity;
        public string   developer_name;
        public string   service_name;
        public string   email;          // always private!
        public bool     is_external;
    }

    /// <summary>The module's own identity — used for server-to-server auth checks.</summary>
    [Table(Accessor = "server_identity", Public = false)]
    public partial struct ServerIdentity
    {
        [PrimaryKey]
        public byte     version;
        public Identity identity;
    }

    /// <summary>Runtime configuration: env, agents_enabled, …</summary>
    [Table(Accessor = "config", Public = false)]
    public partial struct Config
    {
        [PrimaryKey]
        public int    version;
        public string env;             // "dev" bypasses all auth checks
        public bool   agents_enabled;
    }

    /// <summary>Minimal player record — entity_id ↔ identity mapping.</summary>
    [Table(Accessor = "user_state", Public = true)]
    [Index.BTree(Accessor = "by_identity", Columns = [nameof(UserState.identity)])]
    public partial struct UserState
    {
        [PrimaryKey]
        public ulong    entity_id;
        [Unique]                        // one user record per identity
        public Identity identity;
        public bool     can_sign_in;
    }

    /// <summary>Set of entity IDs that are currently signed in.</summary>
    [Table(Accessor = "signed_in_player_state", Public = true)]
    public partial struct SignedInPlayerState
    {
        [PrimaryKey]
        public ulong entity_id;
    }

    /// <summary>Minimal player state: signed-in flag + session timestamps.</summary>
    [Table(Accessor = "player_state", Public = true)]
    public partial struct PlayerState
    {
        [PrimaryKey]
        public ulong entity_id;
        public bool  signed_in;
        public int   session_start_timestamp;  // Unix seconds
        public int   sign_in_timestamp;         // Unix seconds
    }

    // ======================================================================
    //  Auth helpers
    //  Mirrors game/src/game/handlers/authentication.rs
    // ======================================================================

    /// <summary>
    /// <see langword="true"/> when <paramref name="identity"/> holds an
    /// unexpired 24-hour session token (region-module lifetime).
    /// Dev environments always return <see langword="true"/>.
    /// </summary>
    static bool IsAuthenticated(ReducerContext ctx, Identity identity)
        => IsAuthenticatedWithLifetime(ctx, identity, hoursLifetime: 24);

    /// <summary>1-hour variant used by the global module.</summary>
    static bool IsAuthenticatedGlobal(ReducerContext ctx, Identity identity)
        => IsAuthenticatedWithLifetime(ctx, identity, hoursLifetime: 1);

    static bool IsAuthenticatedWithLifetime(
        ReducerContext ctx, Identity identity, int hoursLifetime)
    {
        var config = ctx.Db.config.version.Find(0);
        if (config is null || config.Value.env == "dev")
            return true;

        var entry = ctx.Db.user_authentication_state.identity.Find(identity);
        if (entry is null)
            return false;

        // TimeDuration.Microseconds is a long (µs since the entry was written).
        var elapsed       = ctx.Timestamp.TimeDurationSince(entry.Value.timestamp);
        long lifetimeMicros = (long)hoursLifetime * 3_600L * 1_000_000L;
        return elapsed.Microseconds < lifetimeMicros;
    }

    /// <summary>
    /// <see langword="true"/> when <paramref name="identity"/> has at least
    /// <paramref name="minimumRole"/>.
    /// Dev environments always return <see langword="true"/>.
    /// </summary>
    static bool HasRole(ReducerContext ctx, Identity identity, Role minimumRole)
    {
        var config = ctx.Db.config.version.Find(0);
        if (config is null || config.Value.env == "dev")
            return true;

        return CheckRoleEntry(ctx, identity, minimumRole);
    }

    /// <summary>
    /// Role check that does <em>not</em> short-circuit on dev.
    /// Mirrors <c>has_role_no_dev</c> in the Rust game module.
    /// </summary>
    static bool HasRoleNoDev(ReducerContext ctx, Identity identity, Role minimumRole)
        => CheckRoleEntry(ctx, identity, minimumRole);

    static bool CheckRoleEntry(ReducerContext ctx, Identity identity, Role minimumRole)
    {
        var entry = ctx.Db.identity_role.identity.Find(identity);
        return entry is not null && (int)entry.Value.role >= (int)minimumRole;
    }

    // ── Mutation helpers ──────────────────────────────────────────────────

    /// <summary>Upserts a <see cref="UserAuthenticationState"/> row, refreshing the token.</summary>
    static void UpsertAuthState(ReducerContext ctx, Identity identity)
    {
        if (ctx.Db.user_authentication_state.identity.Find(identity) is { } existing)
        {
            // C# 10+ `with` expression — memberwise copy then field override
            ctx.Db.user_authentication_state.identity.Update(
                existing with { timestamp = ctx.Timestamp });
        }
        else
        {
            ctx.Db.user_authentication_state.Insert(new UserAuthenticationState
            {
                identity  = identity,
                timestamp = ctx.Timestamp,
            });
        }
    }

    /// <summary>Upserts an <see cref="IdentityRole"/> row.</summary>
    static void UpsertIdentityRole(ReducerContext ctx, Identity identity, Role role)
    {
        if (ctx.Db.identity_role.identity.Find(identity) is { } existing)
            ctx.Db.identity_role.identity.Update(existing with { role = role });
        else
            ctx.Db.identity_role.Insert(new IdentityRole { identity = identity, role = role });
    }

    /// <summary>
    /// Force-signs-out <paramref name="identity"/>: removes its
    /// <see cref="SignedInPlayerState"/> row and clears the signed-in flag.
    /// </summary>
    static void SignOutInternal(ReducerContext ctx, Identity identity)
    {
        if (ctx.Db.user_state.identity.Find(identity) is not { } user)
            return;

        var entityId = user.entity_id;
        ctx.Db.signed_in_player_state.entity_id.Delete(entityId);

        if (ctx.Db.player_state.entity_id.Find(entityId) is { } player)
            ctx.Db.player_state.entity_id.Update(player with { signed_in = false });

        Log.Info($"[sign-out] Entity {entityId} signed out.");
    }

    // ======================================================================
    //  Lifecycle reducers
    // ======================================================================

    /// <summary>
    /// Module initialisation.
    /// <list type="number">
    ///   <item>Guards against re-init on non-dev nodes.</item>
    ///   <item>Grants Admin to the deploying identity (<c>ctx.Sender</c>).</item>
    ///   <item>Persists <see cref="ServerIdentity"/>.</item>
    ///   <item>Seeds <see cref="Config"/> (defaults to <c>"dev"</c>).</item>
    /// </list>
    /// </summary>
    [Reducer(ReducerKind.Init)]
    public static void Init(ReducerContext ctx)
    {
        var config = ctx.Db.config.version.Find(0);

        // 1. On non-dev nodes, only the stored server identity or an admin may re-init.
        if (config is { env: not "dev" })
        {
            var server      = ctx.Db.server_identity.version.Find((byte)0);
            bool isServer   = server?.identity == ctx.Sender;
            bool isAdmin    = HasRoleNoDev(ctx, ctx.Sender, Role.Admin);

            if (!isServer && !isAdmin)
                throw new Exception("Caller is not the owner of the database");
        }

        // 2. Grant Admin to the deployer.
        //    In the Rust module, ctx.identity() (module identity) also receives Admin;
        //    SpacetimeDB 2.3 C# exposes the module identity through ctx.Sender during
        //    Init, so both roles collapse to one insert here.
        TryInsertAdminRole(ctx, ctx.Sender);

        // 3. Persist server identity (idempotent).
        if (ctx.Db.server_identity.version.Find((byte)0) is null)
        {
            ctx.Db.server_identity.Insert(new ServerIdentity
            {
                version  = 0,
                identity = ctx.Sender,   // deploying identity becomes the server identity
            });
        }

        // 4. Seed Config (idempotent).
        if (config is null)
        {
            ctx.Db.config.Insert(new Config
            {
                version        = 0,
                env            = "dev",   // change to "prod" before shipping
                agents_enabled = false,
            });
        }

        Log.Info("[init] BitCraft C# auth module initialised.");
    }

    static void TryInsertAdminRole(ReducerContext ctx, Identity identity)
    {
        if (ctx.Db.identity_role.identity.Find(identity) is null)
            ctx.Db.identity_role.Insert(new IdentityRole
            {
                identity = identity,
                role     = Role.Admin,
            });
    }

    // ----------------------------------------------------------------------
    // client_connected
    //
    // Pipeline — matches Rust game/src/lib.rs → identity_connected:
    //   1. Developer / service-account bypass
    //   2. SkipQueue role bypass
    //   3. Block-list check  +  auth-token check  → reject on either failure
    //   4. Re-connection: force sign-out, then allow
    //   5. Unknown identity → reject
    // ----------------------------------------------------------------------
    [Reducer(ReducerKind.ClientConnected)]
    public static void OnClientConnected(ReducerContext ctx)
    {
        var sender = ctx.Sender;

        // 1. Developer bypass.
        if (ctx.Db.developer.identity.Find(sender) is { } dev)
        {
            Log.Info($"[connected] Developer identity: {dev.developer_name} / {dev.service_name}");
            return;
        }

        // 2. SkipQueue role bypass.
        if (HasRole(ctx, sender, Role.SkipQueue))
            return;

        // 3. Block-list + auth token.
        bool blocked       = ctx.Db.blocked_identity.identity.Find(sender) is not null;
        bool authenticated = IsAuthenticated(ctx, sender);

        if (blocked || !authenticated)
        {
            Log.Info($"[connected] Blocking {sender.ToHex()}: blocked={blocked} authenticated={authenticated}");
            throw new Exception("Unauthorized");
        }

        // 4. Already has a user record — handle reconnections.
        if (ctx.Db.user_state.identity.Find(sender) is { } user)
        {
            if (ctx.Db.signed_in_player_state.entity_id.Find(user.entity_id) is not null)
            {
                Log.Info($"[connected] Reconnection for entity {user.entity_id}; forcing sign-out.");
                SignOutInternal(ctx, sender);
            }
            return;
        }

        // 5. No user record and no special permission.
        throw new Exception("Identity with no user or permission is disallowed from connecting");
    }

    [Reducer(ReducerKind.ClientDisconnected)]
    public static void OnClientDisconnected(ReducerContext ctx)
        => SignOutInternal(ctx, ctx.Sender);

    // ======================================================================
    //  Auth-management reducers  (Admin only)
    // ======================================================================

    /// <summary>
    /// Grants or refreshes a session token for <paramref name="identityHex"/>.
    /// Lifetime is 24 h in region modules, 1 h in the global module.
    /// </summary>
    [Reducer]
    public static void Authenticate(ReducerContext ctx, string identityHex)
    {
        RequireRole(ctx, Role.Admin);
        UpsertAuthState(ctx, ParseIdentity(identityHex));
        Log.Info($"[authenticate] Session granted to {identityHex}");
    }

    /// <summary>Assigns a <see cref="Role"/> to an identity identified by hex string.</summary>
    [Reducer]
    public static void SetRoleForIdentity(ReducerContext ctx, string identityHex, Role role)
    {
        RequireRole(ctx, Role.Admin);
        UpsertIdentityRole(ctx, ParseIdentity(identityHex), role);
        Log.Info($"[set_role_for_identity] {role} → {identityHex}");
    }

    /// <summary>Assigns a <see cref="Role"/> to the player with the given entity-id.</summary>
    [Reducer]
    public static void UpdateRoleForPlayer(ReducerContext ctx, ulong playerEntityId, Role role)
    {
        RequireRole(ctx, Role.Admin);

        var user = ctx.Db.user_state.entity_id.Find(playerEntityId)
            ?? throw new Exception($"Player entity {playerEntityId} not found");

        UpsertIdentityRole(ctx, user.identity, role);
        Log.Info($"[update_role_for_player] {role} → entity {playerEntityId}");
    }

    /// <summary>Permanently bars an identity from connecting.</summary>
    [Reducer]
    public static void BlockIdentity(ReducerContext ctx, string identityHex)
    {
        RequireRole(ctx, Role.Admin);
        var identity = ParseIdentity(identityHex);

        if (ctx.Db.blocked_identity.identity.Find(identity) is not null)
            throw new Exception("Identity is already blocked.");

        ctx.Db.blocked_identity.Insert(new BlockedIdentity { identity = identity });
        Log.Info($"[block_identity] Blocked {identityHex}");
    }

    /// <summary>Lifts a block placed by <see cref="BlockIdentity"/>.</summary>
    [Reducer]
    public static void UnblockIdentity(ReducerContext ctx, string identityHex)
    {
        RequireRole(ctx, Role.Admin);
        var identity = ParseIdentity(identityHex);

        if (ctx.Db.blocked_identity.identity.Find(identity) is null)
            throw new Exception("Identity is not currently blocked.");

        ctx.Db.blocked_identity.identity.Delete(identity);
        Log.Info($"[unblock_identity] Unblocked {identityHex}");
    }

    // ======================================================================
    //  sign_in reducer
    //  Mirrors game/src/game/handlers/player/sign_in.rs
    // ======================================================================

    /// <summary>
    /// Called explicitly by the client after <c>client_connected</c> succeeds.
    /// <list type="number">
    ///   <item>Resolves <see cref="UserState"/> for the sender.</item>
    ///   <item>Guards against duplicate sign-in.</item>
    ///   <item>Checks the queue gate (<c>can_sign_in</c>).</item>
    ///   <item>Marks the player signed-in and records Unix-second timestamps.</item>
    /// </list>
    /// </summary>
    [Reducer]
    public static void SignIn(ReducerContext ctx)
    {
        var sender = ctx.Sender;

        var user = ctx.Db.user_state.identity.Find(sender)
            ?? throw new Exception("No user found");

        var entityId = user.entity_id;

        if (ctx.Db.signed_in_player_state.entity_id.Find(entityId) is not null)
            throw new Exception("Already signed in");

        if (!user.can_sign_in)
            throw new Exception("You must join the queue first.");

        var player = ctx.Db.player_state.entity_id.Find(entityId)
            ?? throw new Exception("Invalid player id");

        int nowSecs = UnixSeconds(ctx.Timestamp);
        ctx.Db.player_state.entity_id.Update(player with
        {
            signed_in               = true,
            session_start_timestamp = nowSecs,
            sign_in_timestamp       = nowSecs,
        });

        ctx.Db.signed_in_player_state.Insert(new SignedInPlayerState { entity_id = entityId });
        Log.Info($"[sign_in] Entity {entityId} signed in.");
    }

    // ======================================================================
    //  Shared utilities
    // ======================================================================

    /// <summary>Throws when the caller lacks <paramref name="role"/>.</summary>
    static void RequireRole(ReducerContext ctx, Role role)
    {
        if (!HasRole(ctx, ctx.Sender, role))
            throw new Exception("Invalid permissions");
    }

    /// <summary>
    /// Parses a hex-encoded <see cref="Identity"/> string.
    /// Throws a descriptive <see cref="Exception"/> on failure.
    /// </summary>
    static Identity ParseIdentity(string hex)
    {
        // SpacetimeDB 2.3 C# SDK exposes Identity.TryParse.
        // If your SDK version uses a different name (e.g. Identity.FromHex)
        // replace TryParse with the equivalent call.
        if (!Identity.TryParse(hex, out var identity))
            throw new Exception($"Failed to parse identity: '{hex}'");

        return identity;
    }

    /// <summary>
    /// Converts a <see cref="SpacetimeDB.Timestamp"/> to a Unix epoch value
    /// in whole seconds, matching the Rust <c>game_state::unix(ctx.timestamp)</c> helper.
    /// </summary>
    static int UnixSeconds(SpacetimeDB.Timestamp ts)
        // Timestamp.MicrosecondsSinceEpoch exposes the raw µs-since-Unix-epoch value.
        => (int)(ts.MicrosecondsSinceEpoch / 1_000_000L);
}
