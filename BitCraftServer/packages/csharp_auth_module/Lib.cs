// -----------------------------------------------------------------------
// BitCraft C# SpacetimeDB 2.x Authentication Module
//
// Single-file module following the canonical SpacetimeDB 2.x pattern:
//   public static partial class Module { ... }
//
// Mirrors the Rust auth pipeline found in:
//   game/src/messages/authentication.rs
//   game/src/game/handlers/authentication.rs
//   global_module/src/game/handlers/authentication.rs
//   game/src/lib.rs  (lifecycle)
//   game/src/game/handlers/player/sign_in.rs
// -----------------------------------------------------------------------
using SpacetimeDB;

public static partial class Module
{
    // ================================================================== //
    //  Custom types
    // ================================================================== //

    /// <summary>
    /// Access-level hierarchy. Higher value == more privilege.
    /// Matches the Rust <c>Role</c> enum exactly.
    /// </summary>
    [SpacetimeDB.Type]
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

    // ================================================================== //
    //  Tables
    // ================================================================== //

    // ---------- Shared tables (global → replicated to regions) --------- //

    /// <summary>
    /// Timestamp of the last time an identity was granted a session token.
    /// Session is valid for 24 h in region modules, 1 h in the global module.
    /// </summary>
    [Table(Accessor = "user_authentication_state", Public = false)]
    public partial struct UserAuthenticationState
    {
        [PrimaryKey]
        public Identity identity;
        public SpacetimeDB.Timestamp timestamp;
    }

    /// <summary>
    /// Maps an identity to its highest-granted <see cref="Role"/>.
    /// Public so clients can read their own entry.
    /// </summary>
    [Table(Accessor = "identity_role", Public = true)]
    [SpacetimeDB.Index.BTree(Accessor = "identity", Columns = [nameof(identity)])]
    public partial struct IdentityRole
    {
        [PrimaryKey]
        public Identity identity;
        public Role role;
    }

    /// <summary>Identities permanently barred from connecting.</summary>
    [Table(Accessor = "blocked_identity", Public = false)]
    public partial struct BlockedIdentity
    {
        [PrimaryKey]
        public Identity identity;
    }

    // ---------- Private tables ----------------------------------------- //

    /// <summary>
    /// Service-account / bot identities that bypass the authentication flow.
    /// The <c>email</c> column must remain private (never make this table public).
    /// </summary>
    [Table(Accessor = "developer", Public = false)]
    public partial struct Developer
    {
        [PrimaryKey]
        public Identity identity;
        public string developer_name;
        public string service_name;
        public string email;         // always private!
        public bool   is_external;
    }

    /// <summary>The module's own identity — used for server-to-server auth checks.</summary>
    [Table(Accessor = "server_identity", Public = false)]
    public partial struct ServerIdentity
    {
        [PrimaryKey]
        public byte     version;
        public Identity identity;
    }

    /// <summary>Runtime configuration (env, agents_enabled, …).</summary>
    [Table(Accessor = "config", Public = false)]
    public partial struct Config
    {
        [PrimaryKey]
        public int    version;
        public string env;            // "dev" bypasses all auth checks
        public bool   agents_enabled;
    }

    /// <summary>Minimal player record (entity_id ↔ identity mapping).</summary>
    [Table(Accessor = "user_state", Public = true)]
    [SpacetimeDB.Index.BTree(Accessor = "identity", Columns = [nameof(identity)])]
    public partial struct UserState
    {
        [PrimaryKey]
        public ulong    entity_id;
        public Identity identity;
        public bool     can_sign_in;
    }

    /// <summary>Set of currently signed-in entities.</summary>
    [Table(Accessor = "signed_in_player_state", Public = true)]
    public partial struct SignedInPlayerState
    {
        [PrimaryKey]
        public ulong entity_id;
    }

    /// <summary>Minimal player state (signed-in flag + timestamps).</summary>
    [Table(Accessor = "player_state", Public = true)]
    public partial struct PlayerState
    {
        [PrimaryKey]
        public ulong entity_id;
        public bool  signed_in;
        public int   session_start_timestamp;
        public int   sign_in_timestamp;
    }

    // ================================================================== //
    //  Auth helper functions (mirrors Rust game/handlers/authentication.rs)
    // ================================================================== //

    /// <summary>
    /// Returns <c>true</c> when <paramref name="identity"/> holds an unexpired
    /// 24-hour session token (region module lifetime).
    /// Dev environments always return <c>true</c>.
    /// </summary>
    static bool IsAuthenticated(ReducerContext ctx, Identity identity)
        => IsAuthenticatedWithLifetime(ctx, identity, TimeSpan.FromHours(24));

    /// <summary>
    /// 1-hour variant used by the global module.
    /// </summary>
    static bool IsAuthenticatedGlobal(ReducerContext ctx, Identity identity)
        => IsAuthenticatedWithLifetime(ctx, identity, TimeSpan.FromHours(1));

    static bool IsAuthenticatedWithLifetime(ReducerContext ctx, Identity identity, TimeSpan lifetime)
    {
        var config = ctx.Db.config.version.Find(0);
        if (config is null || config.Value.env == "dev")
            return true;

        var entry = ctx.Db.user_authentication_state.identity.Find(identity);
        if (entry is null)
            return false;

        var elapsed = ctx.Timestamp.TimeDurationSince(entry.Value.timestamp);
        return elapsed.Microseconds < (long)lifetime.TotalMicroseconds;
    }

    /// <summary>
    /// Returns <c>true</c> when <paramref name="identity"/> has at least
    /// <paramref name="minimumRole"/> access.
    /// Dev environments always return <c>true</c>.
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

    /// <summary>
    /// Upserts a <see cref="UserAuthenticationState"/> row, refreshing the token.
    /// </summary>
    static void UpsertAuthState(ReducerContext ctx, Identity identity)
    {
        var existing = ctx.Db.user_authentication_state.identity.Find(identity);
        if (existing is not null)
        {
            var updated = existing.Value;
            updated.timestamp = ctx.Timestamp;
            ctx.Db.user_authentication_state.identity.Update(updated);
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
        var existing = ctx.Db.identity_role.identity.Find(identity);
        if (existing is not null)
        {
            var updated = existing.Value;
            updated.role = role;
            ctx.Db.identity_role.identity.Update(updated);
        }
        else
        {
            ctx.Db.identity_role.Insert(new IdentityRole
            {
                identity = identity,
                role     = role,
            });
        }
    }

    /// <summary>Force-signs-out <paramref name="identity"/>.</summary>
    static void SignOutInternal(ReducerContext ctx, Identity identity)
    {
        var user = ctx.Db.user_state.identity.Find(identity);
        if (user is null) return;

        ctx.Db.signed_in_player_state.entity_id.Delete(user.Value.entity_id);

        var player = ctx.Db.player_state.entity_id.Find(user.Value.entity_id);
        if (player is not null)
        {
            var updated = player.Value;
            updated.signed_in = false;
            ctx.Db.player_state.entity_id.Update(updated);
        }

        Log.Info($"[sign-out] Entity {user.Value.entity_id} signed out.");
    }

    // ================================================================== //
    //  Lifecycle reducers
    // ================================================================== //

    /// <summary>
    /// Module initialisation.
    /// 1. Guards against re-init on non-dev nodes.
    /// 2. Grants the deployer + module identity Admin role.
    /// 3. Persists ServerIdentity.
    /// 4. Seeds Config ("dev" by default).
    /// </summary>
    [Reducer(ReducerKind.Init)]
    public static void Init(ReducerContext ctx)
    {
        // 1. On non-dev nodes, only owner / admin may re-init.
        var config = ctx.Db.config.version.Find(0);
        if (config is not null && config.Value.env != "dev")
        {
            var server = ctx.Db.server_identity.version.Find(0);
            if (server is not null &&
                server.Value.identity != ctx.Sender &&
                !HasRoleNoDev(ctx, ctx.Sender, Role.Admin))
            {
                throw new Exception("Caller is not the owner of the database");
            }
        }

        // 2. Grant Admin to deployer + module identity.
        TryInsertAdminRole(ctx, ctx.Sender);
        TryInsertAdminRole(ctx, ctx.Identity());

        // 3. Persist server identity.
        if (ctx.Db.server_identity.version.Find(0) is null)
        {
            ctx.Db.server_identity.Insert(new ServerIdentity
            {
                version  = 0,
                identity = ctx.Identity(),
            });
        }

        // 4. Seed Config.
        if (config is null)
        {
            ctx.Db.config.Insert(new Config
            {
                version       = 0,
                env           = "dev",   // bootstrap default – update to "prod" before launch
                agents_enabled = false,
            });
        }

        Log.Info("[init] BitCraft C# auth module initialised.");
    }

    static void TryInsertAdminRole(ReducerContext ctx, Identity identity)
    {
        if (ctx.Db.identity_role.identity.Find(identity) is null)
        {
            ctx.Db.identity_role.Insert(new IdentityRole
            {
                identity = identity,
                role     = Role.Admin,
            });
        }
    }

    // ------------------------------------------------------------------ //
    // client_connected
    //
    // Pipeline (matches Rust game/src/lib.rs identity_connected):
    //   1. Developer / service-account bypass
    //   2. SkipQueue role bypass
    //   3. Block-list check  +  4. Auth-token check  → reject if either fails
    //   5. Re-connection: force sign-out then allow
    //   6. Unknown identity → reject
    // ------------------------------------------------------------------ //
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

        // 3 & 4. Block-list + auth token.
        bool isBlocked       = ctx.Db.blocked_identity.identity.Find(sender) is not null;
        bool isAuthenticated = IsAuthenticated(ctx, sender);

        if (isBlocked || !isAuthenticated)
        {
            Log.Info($"[connected] Blocking {sender.ToHex()}: blocked={isBlocked} authenticated={isAuthenticated}");
            throw new Exception("Unauthorized");
        }

        // 5. Already has a user record – handle re-connections.
        if (ctx.Db.user_state.identity.Find(sender) is { } user)
        {
            if (ctx.Db.signed_in_player_state.entity_id.Find(user.entity_id) is not null)
            {
                Log.Info($"[connected] Re-connection for entity {user.entity_id}; forcing sign-out.");
                SignOutInternal(ctx, sender);
            }
            return;
        }

        // 6. No user record and no permission.
        throw new Exception("Identity with no user or permission is disallowed from connecting");
    }

    // ------------------------------------------------------------------ //
    // client_disconnected
    // ------------------------------------------------------------------ //
    [Reducer(ReducerKind.ClientDisconnected)]
    public static void OnClientDisconnected(ReducerContext ctx)
    {
        SignOutInternal(ctx, ctx.Sender);
    }

    // ================================================================== //
    //  Auth-management reducers
    // ================================================================== //

    /// <summary>
    /// Grant (or refresh) a session token for <paramref name="identityHex"/>.
    /// Admin only.
    /// </summary>
    [Reducer]
    public static void Authenticate(ReducerContext ctx, string identityHex)
    {
        if (!HasRole(ctx, ctx.Sender, Role.Admin))
            throw new Exception("Invalid permissions");

        if (!Identity.TryParse(identityHex, out var identity))
            throw new Exception("Failed to parse identity");

        UpsertAuthState(ctx, identity);
        Log.Info($"[authenticate] Session granted to {identityHex}");
    }

    /// <summary>Assign a <see cref="Role"/> to an identity by hex string. Admin only.</summary>
    [Reducer]
    public static void SetRoleForIdentity(ReducerContext ctx, string identityHex, Role role)
    {
        if (!HasRole(ctx, ctx.Sender, Role.Admin))
            throw new Exception("Invalid permissions");

        if (!Identity.TryParse(identityHex, out var identity))
            throw new Exception("Failed to parse identity");

        UpsertIdentityRole(ctx, identity, role);
        Log.Info($"[set_role_for_identity] {role} → {identityHex}");
    }

    /// <summary>Assign a <see cref="Role"/> to a player by entity-id. Admin only.</summary>
    [Reducer]
    public static void UpdateRoleForPlayer(ReducerContext ctx, ulong playerEntityId, Role role)
    {
        if (!HasRole(ctx, ctx.Sender, Role.Admin))
            throw new Exception("Invalid permissions");

        var user = ctx.Db.user_state.entity_id.Find(playerEntityId)
            ?? throw new Exception("Player not found");

        UpsertIdentityRole(ctx, user.identity, role);
        Log.Info($"[update_role_for_player] {role} → entity {playerEntityId}");
    }

    /// <summary>Permanently bar an identity from connecting. Admin only.</summary>
    [Reducer]
    public static void BlockIdentity(ReducerContext ctx, string identityHex)
    {
        if (!HasRole(ctx, ctx.Sender, Role.Admin))
            throw new Exception("Invalid permissions");

        if (!Identity.TryParse(identityHex, out var identity))
            throw new Exception("Failed to parse identity");

        if (ctx.Db.blocked_identity.identity.Find(identity) is not null)
            throw new Exception("Identity is already blocked.");

        ctx.Db.blocked_identity.Insert(new BlockedIdentity { identity = identity });
        Log.Info($"[block_identity] Blocked {identityHex}");
    }

    /// <summary>Lift a block placed by <see cref="BlockIdentity"/>. Admin only.</summary>
    [Reducer]
    public static void UnblockIdentity(ReducerContext ctx, string identityHex)
    {
        if (!HasRole(ctx, ctx.Sender, Role.Admin))
            throw new Exception("Invalid permissions");

        if (!Identity.TryParse(identityHex, out var identity))
            throw new Exception("Failed to parse identity");

        if (ctx.Db.blocked_identity.identity.Find(identity) is null)
            throw new Exception("Identity is not currently blocked.");

        ctx.Db.blocked_identity.identity.Delete(identity);
        Log.Info($"[unblock_identity] Unblocked {identityHex}");
    }

    // ================================================================== //
    //  sign_in reducer
    //  Mirrors game/src/game/handlers/player/sign_in.rs
    // ================================================================== //

    /// <summary>
    /// Called explicitly by the client after connecting.
    /// Pipeline:
    ///   1. Resolve UserState
    ///   2. Server-availability check
    ///   3. Duplicate sign-in guard
    ///   4. Queue gate (user.can_sign_in)
    ///   5. Mark player signed in
    /// </summary>
    [Reducer]
    public static void SignIn(ReducerContext ctx)
    {
        var sender = ctx.Sender;

        // 1. Must have a user record.
        var user = ctx.Db.user_state.identity.Find(sender)
            ?? throw new Exception("No user found");

        var actorId = user.entity_id;

        // 2. Duplicate sign-in guard.
        if (ctx.Db.signed_in_player_state.entity_id.Find(actorId) is not null)
            throw new Exception("Already signed in");

        // 3. Queue gate.
        if (!user.can_sign_in)
            throw new Exception("You must join the queue first.");

        // 4. Mark signed in.
        var player = ctx.Db.player_state.entity_id.Find(actorId)
            ?? throw new Exception("Invalid player id");

        var updated = player;
        updated.signed_in             = true;
        updated.session_start_timestamp = UnixSeconds(ctx.Timestamp);
        updated.sign_in_timestamp       = UnixSeconds(ctx.Timestamp);
        ctx.Db.player_state.entity_id.Update(updated);

        ctx.Db.signed_in_player_state.Insert(new SignedInPlayerState { entity_id = actorId });

        Log.Info($"[sign_in] Entity {actorId} signed in.");
    }

    // ================================================================== //
    //  Utility
    // ================================================================== //

    static int UnixSeconds(SpacetimeDB.Timestamp ts)
        => (int)(ts.TimeDurationSince(SpacetimeDB.Timestamp.UnixEpoch).Microseconds / 1_000_000L);
}
