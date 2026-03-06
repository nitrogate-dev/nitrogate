// This file tests the NitroGate Secrets Scanner
// Each line contains a different type of secret pattern

const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
const PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGT6AjVJlAkBBE0K1pGf
-----END RSA PRIVATE KEY-----`;
const DB_CONN = "postgresql://admin:supersecretpassword@db.example.com:5432/production";
