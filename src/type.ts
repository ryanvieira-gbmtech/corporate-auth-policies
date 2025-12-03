// src/type.ts
import type { JwtPayload } from "jsonwebtoken";

export interface KeycloakResourceAccess {
  [clientId: string]: { roles: string[] };
}

export interface KeycloakJwtPayload extends JwtPayload {
  resource_access?: KeycloakResourceAccess;
}
