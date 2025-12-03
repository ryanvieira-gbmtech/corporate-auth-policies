// tests/JwtValidator.basic.spec.ts
import { describe, it, expect, vi, beforeEach } from "vitest";
import { JwtValidator } from "../src/JwtValidator";
import { createMockReq } from "./testUtils";

describe("JwtValidator - Métodos básicos e construtor", () => {
  describe("Construtor", () => {
    it("deve criar instância com configurações padrão", () => {
      const validator = new JwtValidator({
        jwksUri: "https://keycloak.local/jwks",
        issuer: "https://keycloak.local/issuer"
      });

      expect(validator).toBeInstanceOf(JwtValidator);
    });

    it("deve criar instância com roleErrorMap vazio por padrão", () => {
      const validator = new JwtValidator({
        jwksUri: "https://keycloak.local/jwks",
        issuer: "https://keycloak.local/issuer"
      });

      // roleErrorMap deve ser um objeto vazio por padrão
      expect((validator as any).roleErrorMap).toEqual({});
    });

    it("deve criar instância com roleErrorMap customizado", () => {
      const roleErrorMap = {
        "hub-agendamentos:admin": "HUB_FORBIDDEN_0001"
      };

      const validator = new JwtValidator({
        jwksUri: "https://keycloak.local/jwks",
        issuer: "https://keycloak.local/issuer",
        roleErrorMap
      });

      expect((validator as any).roleErrorMap).toEqual(roleErrorMap);
    });
  });

  describe("extractToken", () => {
    let validator: JwtValidator;

    beforeEach(() => {
      validator = new JwtValidator({
        jwksUri: "https://fake/jwks",
        issuer: "https://fake/issuer"
      });
    });

    it("deve extrair token do header Authorization (lowercase)", () => {
      const req = createMockReq({
        headers: {
          authorization: "Bearer token-123"
        }
      });

      const token = validator.extractToken(req);
      expect(token).toBe("token-123");
    });

    it("deve extrair token do header Authorization (uppercase)", () => {
      const req = createMockReq({
        headers: {
          Authorization: "Bearer token-456"
        }
      });

      const token = validator.extractToken(req);
      expect(token).toBe("token-456");
    });

    it("deve retornar null quando não há header Authorization", () => {
      const req = createMockReq();
      const token = validator.extractToken(req);
      expect(token).toBeNull();
    });

    it("deve retornar null quando header não começa com Bearer", () => {
      const req = createMockReq({
        headers: {
          authorization: "Basic token-789"
        }
      });

      const token = validator.extractToken(req);
      expect(token).toBeNull();
    });

    it("deve retornar null quando header está vazio", () => {
      const req = createMockReq({
        headers: {
          authorization: ""
        }
      });

      const token = validator.extractToken(req);
      expect(token).toBeNull();
    });

    it("deve retornar null quando header tem apenas Bearer", () => {
      const req = createMockReq({
        headers: {
          authorization: "Bearer "
        }
      });

      const token = validator.extractToken(req);
      expect(token).toBe("");
    });

    it("deve extrair token com espaços", () => {
      const req = createMockReq({
        headers: {
          authorization: "Bearer  token-with-spaces  "
        }
      });

      const token = validator.extractToken(req);
      expect(token).toBe(" token-with-spaces  ");
    });
  });
});