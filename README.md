# Firebase JWT

A library to help parse JWT tokens from Firebase in Rust 

## Install 

```cargo add firebase-jwt```

## Axum Middleware 

See the [example](./example) for use with Axum, it's a case of setting your Google project id and then adding the middleware to the Router

```rust
    let app_state = AppState::new("your-project-id".to_string());

    let jwt_routes = Router::new()
        .route("/auth/example", get(auth))
        .layer(middleware::from_fn_with_state(app_state.expect("Unable to get app state").clone(), axum_auth_middleware));
```