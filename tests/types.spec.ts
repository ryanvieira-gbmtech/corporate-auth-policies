// tests/types.spec.ts
import { describe, it, expect, vi } from "vitest";
import type {
  KeycloakResourceAccess,
  KeycloakJwtPayload
} from "../src/types";
import type { JwtPayload } from "jsonwebtoken";

// Este é mais um teste de tipos do que de runtime
// Usamos o vitest para validar que os tipos funcionam como esperado

describe("Types", () => {
  describe("KeycloakResourceAccess", () => {
    it("deve permitir estrutura de resource_access do Keycloak", () => {
      const resourceAccess: KeycloakResourceAccess = {
        "hub-agendamentos": {
          roles: ["admin", "viewer"]
        },
        "conta-digital": {
          roles: ["financeiro", "gerente"]
        },
        "account": {
          roles: ["manage-account", "view-profile"]
        }
      };

      expect(resourceAccess["hub-agendamentos"].roles).toEqual(["admin", "viewer"]);
      expect(resourceAccess["conta-digital"].roles).toEqual(["financeiro", "gerente"]);
      expect(Object.keys(resourceAccess)).toHaveLength(3);
    });

    it("deve permitir resource_access vazio", () => {
      const resourceAccess: KeycloakResourceAccess = {};
      expect(Object.keys(resourceAccess)).toHaveLength(0);
    });

    it("deve permitir clients com roles vazias", () => {
      const resourceAccess: KeycloakResourceAccess = {
        "client-without-roles": {
          roles: []
        }
      };

      expect(resourceAccess["client-without-roles"].roles).toEqual([]);
    });
  });

  describe("KeycloakJwtPayload", () => {
    it("deve estender JwtPayload corretamente", () => {
      // Cria um mock que simula o JwtPayload base
      const basePayload: JwtPayload = {
        iss: "https://keycloak.example.com/realms/master",
        sub: "user-123",
        aud: "account",
        exp: 1704067200,
        iat: 1704063600,
        auth_time: 1704063600,
        jti: "jwt-id-123",
        azp: "client-id",
        scope: "openid profile email",
        email_verified: true,
        name: "John Doe",
        preferred_username: "johndoe",
        given_name: "John",
        family_name: "Doe",
        email: "john.doe@example.com"
      };

      const keycloakPayload: KeycloakJwtPayload = {
        ...basePayload,
        resource_access: {
          "hub-agendamentos": {
            roles: ["admin", "viewer"]
          },
          "account": {
            roles: ["manage-account"]
          }
        }
      };

      expect(keycloakPayload.sub).toBe("user-123");
      expect(keycloakPayload.resource_access).toBeDefined();
      expect(keycloakPayload.resource_access!["hub-agendamentos"].roles).toContain("admin");
    });

    it("deve permitir payload sem resource_access", () => {
      const payload: KeycloakJwtPayload = {
        iss: "https://keycloak.example.com",
        sub: "user-456",
        aud: "client",
        exp: 1704067200,
        iat: 1704063600
        // resource_access é opcional
      };

      expect(payload.sub).toBe("user-456");
      expect(payload.resource_access).toBeUndefined();
    });

    it("deve permitir payload com resource_access undefined", () => {
      const payload: KeycloakJwtPayload = {
        iss: "https://keycloak.example.com",
        sub: "user-789",
        aud: "client",
        exp: 1704067200,
        iat: 1704063600,
        resource_access: undefined
      };

      expect(payload.sub).toBe("user-789");
      expect(payload.resource_access).toBeUndefined();
    });

    it("deve permitir payload com resource_access vazio", () => {
      const payload: KeycloakJwtPayload = {
        iss: "https://keycloak.example.com",
        sub: "user-999",
        aud: "client",
        exp: 1704067200,
        iat: 1704063600,
        resource_access: {}
      };

      expect(payload.sub).toBe("user-999");
      expect(payload.resource_access).toEqual({});
    });

    it("deve funcionar com realm_access também (se necessário)", () => {
      // Adicionando realm_access como propriedade extra
      const payloadWithRealmAccess = {
        iss: "https://keycloak.example.com",
        sub: "user-111",
        aud: "client",
        exp: 1704067200,
        iat: 1704063600,
        resource_access: {
          "client-1": { roles: ["role1"] }
        },
        realm_access: {
          roles: ["offline_access", "uma_authorization"]
        }
      } as KeycloakJwtPayload; // Cast para o tipo

      expect(payloadWithRealmAccess.sub).toBe("user-111");
      expect(payloadWithRealmAccess.resource_access!["client-1"].roles).toEqual(["role1"]);
      // Note: realm_access não está no tipo, mas TypeScript permite propriedades extras
    });
  });

  describe("Integração com JwtValidator", () => {
    it("deve usar KeycloakJwtPayload no verifyToken", () => {
      // Mock da função verifyToken para testar o tipo de retorno
      const mockVerifyToken = vi.fn().mockResolvedValue({
        sub: "user-123",
        aud: "hub-agendamentos",
        resource_access: {
          "hub-agendamentos": {
            roles: ["admin"]
          }
        }
      } as KeycloakJwtPayload);

      // Teste que o mock retorna o tipo correto
      expect(mockVerifyToken).toBeDefined();
      
      // Verificação de tipo em runtime (usando o mock)
      const payloadPromise = mockVerifyToken();
      
      return payloadPromise.then((payload: KeycloakJwtPayload) => {
        expect(payload.sub).toBe("user-123");
        expect(payload.resource_access).toBeDefined();
        expect(payload.resource_access!["hub-agendamentos"].roles).toContain("admin");
      });
    });

    it("deve extrair roles corretamente de KeycloakJwtPayload", () => {
      const payload: KeycloakJwtPayload = {
        sub: "user-123",
        resource_access: {
          "hub-agendamentos": {
            roles: ["admin", "viewer", "editor"]
          },
          "conta-digital": {
            roles: ["financeiro"]
          }
        }
      };

      // Simula a lógica de extração de roles do JwtValidator
      const clientId = "hub-agendamentos";
      const resourceAccess = payload.resource_access ?? {};
      const client = resourceAccess[clientId] ?? {};
      const roles: string[] = client.roles ?? [];

      expect(roles).toEqual(["admin", "viewer", "editor"]);
      expect(roles).toContain("admin");
      expect(roles).not.toContain("financeiro");
    });

    it("deve lidar com resource_access undefined ao extrair roles", () => {
      const payload: KeycloakJwtPayload = {
        sub: "user-123"
        // sem resource_access
      };

      const clientId = "hub-agendamentos";
      const resourceAccess = payload.resource_access ?? {};
      const client = resourceAccess[clientId] ?? {};
      const roles: string[] = client.roles ?? [];

      expect(roles).toEqual([]);
      expect(roles).toHaveLength(0);
    });

    it("deve lidar com client não existente ao extrair roles", () => {
      const payload: KeycloakJwtPayload = {
        sub: "user-123",
        resource_access: {
          "outro-client": {
            roles: ["admin"]
          }
        }
      };

      const clientId = "hub-agendamentos";
      const resourceAccess = payload.resource_access ?? {};
      const client = resourceAccess[clientId] ?? {};
      const roles: string[] = client.roles ?? [];

      expect(roles).toEqual([]);
    });

    it("deve lidar com roles undefined para um client existente", () => {
      const payload = {
        sub: "user-123",
        resource_access: {
          "hub-agendamentos": {
            // roles não definido
          }
        }
      } as KeycloakJwtPayload;

      const clientId = "hub-agendamentos";
      const resourceAccess = payload.resource_access ?? {};
      const client = resourceAccess[clientId] ?? {};
      const roles: string[] = client.roles ?? [];

      expect(roles).toEqual([]);
    });
  });

  describe("Compatibilidade com cenários reais", () => {
    it("deve aceitar payload real do Keycloak", () => {
      const realKeycloakPayload = {
        "exp": 1704067200,
        "iat": 1704063600,
        "auth_time": 1704063600,
        "jti": "jwt-id-real",
        "iss": "https://keycloak.nstech.com.br/realms/master",
        "aud": ["hub-agendamentos", "account"],
        "sub": "user-real-123",
        "typ": "Bearer",
        "azp": "hub-agendamentos",
        "session_state": "session-id-123",
        "acr": "1",
        "allowed-origins": ["https://app.nstech.com.br"],
        "realm_access": {
          "roles": ["offline_access", "uma_authorization"]
        },
        "resource_access": {
          "hub-agendamentos": {
            "roles": ["admin", "viewer", "editor"]
          },
          "account": {
            "roles": ["manage-account", "view-profile"]
          }
        },
        "scope": "openid profile email",
        "sid": "session-id-123",
        "email_verified": true,
        "name": "Usuário Real",
        "preferred_username": "usuario.real",
        "given_name": "Usuário",
        "family_name": "Real",
        "email": "usuario.real@nstech.com.br"
      } as KeycloakJwtPayload;

      expect(realKeycloakPayload.sub).toBe("user-real-123");
      expect(realKeycloakPayload.resource_access).toBeDefined();
      expect(realKeycloakPayload.resource_access!["hub-agendamentos"].roles).toEqual(
        ["admin", "viewer", "editor"]
      );
      expect(realKeycloakPayload.aud).toEqual(["hub-agendamentos", "account"]);
    });

    it("deve lidar com audience como string ou array", () => {
      // Teste com audience como string
      const payloadWithStringAud: KeycloakJwtPayload = {
        sub: "user-1",
        aud: "hub-agendamentos"
      };

      // Teste com audience como array
      const payloadWithArrayAud: KeycloakJwtPayload = {
        sub: "user-2",
        aud: ["hub-agendamentos", "account"]
      };

      expect(payloadWithStringAud.aud).toBe("hub-agendamentos");
      expect(Array.isArray(payloadWithArrayAud.aud)).toBe(true);
      expect(payloadWithArrayAud.aud).toContain("hub-agendamentos");
    });
  });
});