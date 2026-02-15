-- name: GetUserByCredentials :one
SELECT id FROM users
WHERE username = $1 AND password = $2;
