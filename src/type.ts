// src/type.ts
import type { JwtPayload } from "jsonwebtoken";

export interface KeycloakResourceAccess {
	[clientId: string]: { roles: string[] };
}

export interface KeycloakJwtPayload extends JwtPayload {
	resource_access?: KeycloakResourceAccess;
}

export interface JwtValidatorOptions {
	jwksUri: string; // URL do JWKS do Keycloak
	issuer: string; // Issuer esperado (realm)
	audience?: string; // opcional: audience padrão
}
