// tests/testUtils.ts
import type { Request, Response, NextFunction } from "express";
import { vi } from "vitest";

export function createMockReq(
  overrides?: Partial<Request>
): Request {
  return {
    method: "GET",
    url: "/test",
    headers: {},
    body: {},
    params: {},
    query: {},
    originalUrl: "/test",
    ...overrides
  } as unknown as Request;
}

export function createMockRes() {
  const res: Partial<Response> = {};
  res.statusCode = 200;

  const statusFn = vi.fn((code: number) => {
    res.statusCode = code;
    return res as Response;
  });

  res.status = statusFn;

  let jsonBody: any;
  const jsonFn = vi.fn((body: any) => {
    jsonBody = body;
    return res as Response;
  });

  res.json = jsonFn;

  // Métodos adicionais do Express Response
  res.send = vi.fn(() => res as Response);
  res.end = vi.fn(() => res as Response);
  res.setHeader = vi.fn(() => res as Response);
  res.getHeader = vi.fn();
  res.removeHeader = vi.fn();

  return {
    res: res as Response,
    getJson: () => jsonBody,
    getStatus: () => res.statusCode,
    statusFn,
    jsonFn
  };
}

export function createMockNext() {
  return vi.fn<NextFunction>();
}