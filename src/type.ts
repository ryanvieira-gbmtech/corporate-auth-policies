// src/type.ts
import type { JwtPayload } from "jsonwebtoken";

export interface KeycloakResourceAccess {
  [clientId: string]: { roles: string[] };
}

export interface KeycloakJwtPayload extends JwtPayload {
  resource_access?: KeycloakResourceAccess;
}

export interface RoleErrorMap {
  [roleKey: string]: string; // ex: "hub-agendamentos:admin" -> "HUB_FORBIDDEN_0007"
}

export interface JwtValidatorOptions {
  jwksUri: string;                     // URL do JWKS do Keycloak
  issuer: string;                      // Issuer esperado (realm)
  audience?: string;                   // opcional: audience padrão
  roleErrorMap?: RoleErrorMap;         // mapa de roles -> errorCode
}
