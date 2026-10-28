<?php
/**
 * Lane 4 — Class B fixture: merge-order logic flaw (CWE-915).
 *
 * User-controlled fields are merged into a config object where 'role'
 * is set first and 'is_admin' overwrites it, bypassing the role check.
 *
 * This illustrates CWE-915: improperly controlled modification of
 * dynamically-determined object attributes. The merge order allows
 * user input to control security-relevant fields after they've been
 * ostensibly set.
 */
function merge_user_config($user_input, &$config) {
    // Merge order: role first, then is_admin flag overwrites.
    if (isset($user_input['role'])) {
        $config['role'] = $user_input['role'];
    } else {
        $config['role'] = 'subscriber';
    }

    // Later code may check $config['role'] == 'admin' to grant privileges,
    // but the is_admin flag below can override that decision.
    if (isset($user_input['is_admin'])) {
        $config['is_admin'] = $user_input['is_admin'];
    } else {
        $config['is_admin'] = false;
    }

    // Additional fields that could be exploited.
    if (isset($user_input['permissions'])) {
        $config['permissions'] = $user_input['permissions'];
    }

    // The merge order creates a logic flaw: even if role is 'subscriber',
    // is_admin can be set to true by user input, bypassing the role check.
}

/**
 * Example of the vulnerability in action.
 */
function process_user_settings($request) {
    $config = [];

    // Attacker sends: ['role' => 'subscriber', 'is_admin' => true]
    merge_user_config($request, $config);

    // This check is bypassed because is_admin was set after role.
    if ($config['role'] === 'admin') {
        grant_admin_privileges();
    }

    // But this check also passes due to the is_admin override.
    if (!empty($config['is_admin'])) {
        grant_admin_privileges(); // VULNERABLE: attacker controls this path.
    }
}

function grant_admin_privileges() {
    // Grant admin access — should not be reachable via user input.
    update_option('admin_access_granted', true);
}
