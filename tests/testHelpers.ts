// tests/testHelpers.ts
import { vi } from "vitest";
import { mockJwks, mockJwtVerifySuccess } from "./mocks";

export async function setupJwtTest(payload: any) {
  mockJwks();
  mockJwtVerifySuccess(payload);
  
  // Importar após configurar mocks
  const { JwtValidator } = await import("../src/JwtValidator");
  return JwtValidator;
}