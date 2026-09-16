#[test]
fn test_extracts_django_urlpatterns() {
    // Test Django urlpatterns extraction
    let content = r#"
        from django.urls import path, re_path, url

        urlpatterns = [
            path('admin/', admin.site.urls),
            re_path(r'^api/v1/', api_handler),
            url(r'^legacy/', legacy_handler),
        ]
    "#;

    let cfg = HookRegistryLanguageConfig {
        hook_label: "urlpatterns".to_string(),
        registrations: vec![
            r"(?si)path\s*\(\s*[\x27\x22](?P<hook>[^\x27\x22]+)[\x27\x22]".to_string(),
            r"(?si)re_path\s*\(\s*r?[\x27\x22](?P<hook>[^\x27\x22]+)[\x27\x22]".to_string(),
            r"(?si)url\s*\(\s*r?[\x27\x22](?P<hook>[^\x27\x22]+)[\x27\x22]".to_string(),
        ],
        handler_patterns: Some(vec![
            r",\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*[\),]".to_string(),
        ]),
    };

    let regs = hook_registry::extract_hooks(content, &cfg);

    assert!(regs.len() >= 3, "Expected at least 3 Django registrations");
    let handlers: Vec<&str> = regs.iter().map(|r| r.handler.as_str()).collect();
    assert!(handlers.contains(&"admin"));
    assert!(handlers.contains(&"api_handler"));
    assert!(handlers.contains(&"legacy_handler"));
}

#[test]
fn test_extracts_laravel_routes() {
    // Test Laravel Route::get/post extraction
    let content = r#"
        Route::get('/users', 'UserController@index');
        Route::post('/users', 'UserController@store');
        Route::patch('/users/{id}', 'UserController@update');
    "#;

    let cfg = HookRegistryLanguageConfig {
        hook_label: "rest_route".to_string(),
        registrations: vec![
            r"(?si)Route::(?:get|post|put|patch|delete)\s*\(\s*[\x27\x22](?P<hook>[^\x27\x22]+)[\x27\x22]".to_string(),
        ],
        handler_patterns: Some(vec![
            r",\s*[\x27\x22]([a-zA-Z_][a-zA-Z0-9_]*@[a-zA-Z_][a-zA-Z0-9_]*)[\x27\x22]".to_string(),
        ]),
    };

    let regs = hook_registry::extract_hooks(content, &cfg);

    assert_eq!(regs.len(), 3, "Expected 3 Laravel registrations");
    let handlers: Vec<&str> = regs.iter().map(|r| r.handler.as_str()).collect();
    assert!(handlers.contains(&"UserController@index"));
    assert!(handlers.contains(&"UserController@store"));
    assert!(handlers.contains(&"UserController@update"));
}

#[test]
fn test_unknown_language_noop() {
    // Empty registrations should produce no results (simulating unknown language)
    let content = r#"
        add_action('wp_ajax_test', 'test_handler');
        register_rest_route('ns', '/v1', array('callback' => 'handler'));
    "#;

    let cfg = HookRegistryLanguageConfig {
        hook_label: "entry_point".to_string(),
        registrations: vec![],
        handler_patterns: None,
    };

    let regs = hook_registry::extract_hooks(content, &cfg);

    assert_eq!(regs.len(), 0, "Empty registrations should produce empty result");
}
