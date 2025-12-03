// tests/JwtValidator.verifyToken.spec.ts
import { describe, it, expect, vi, beforeEach } from "vitest";
import jwt from "jsonwebtoken";
import { JwtValidator } from "../src/JwtValidator";

describe("JwtValidator.verifyToken (comportamento do callback jwt.verify)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("deve resolver com o payload quando jwt.verify decodificar com sucesso", async () => {
    // mock do jwt.verify chamando o callback final com decoded
    vi.spyOn(jwt, "verify").mockImplementation(
      // @ts-expect-error simplificando a assinatura pra teste
      (token: string, getKey: any, options: any, cb: any) => {
        // não precisamos simular getKey nem jwks aqui
        cb(null, {
          sub: "user-123",
          aud: "hub",
        });
      }
    );

    const validator = new JwtValidator({
      jwksUri: "https://fake/jwks",
      issuer: "https://fake/issuer",
    });

    const payload = await validator.verifyToken("fake-token");

    expect(payload.sub).toBe("user-123");
    expect(payload.aud).toBe("hub");
  });

  it("deve rejeitar com code=TOKEN_INVALID quando jwt.verify retornar erro", async () => {
    vi.spyOn(jwt, "verify").mockImplementation(
      // @ts-expect-error assinatura simplificada
      (token: string, getKey: any, options: any, cb: any) => {
        const err: any = new Error("invalid signature");
        cb(err, undefined);
      }
    );

    const validator = new JwtValidator({
      jwksUri: "https://fake/jwks",
      issuer: "https://fake/issuer",
    });

    await expect(validator.verifyToken("fake-token")).rejects.toMatchObject({
      code: "TOKEN_INVALID",
    });
  });

  it("deve rejeitar com code=TOKEN_INVALID quando decoded vier undefined (mesmo sem erro explícito)", async () => {
    vi.spyOn(jwt, "verify").mockImplementation(
      // @ts-expect-error assinatura simplificada
      (token: string, getKey: any, options: any, cb: any) => {
        cb(null, undefined);
      }
    );

    const validator = new JwtValidator({
      jwksUri: "https://fake/jwks",
      issuer: "https://fake/issuer",
    });

    await expect(validator.verifyToken("fake-token")).rejects.toMatchObject({
      code: "TOKEN_INVALID",
    });
  });
});
