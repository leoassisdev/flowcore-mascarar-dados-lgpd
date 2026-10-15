// mascarar-lgpd.test.ts · Criado por FlowCore Soluções LTDA · flowcoresolucoes.com.br/codigos · licença MIT
import { describe, expect, it } from "vitest";
import { luhnValido, mascararObjeto, mascararTexto, REDACTED } from "./mascarar-lgpd";

describe("mascarar-lgpd", () => {
  it("mascara CPF formatado e cru (só se o DV bate)", () => {
    expect(mascararTexto("CPF 529.982.247-25 ok")).toBe("CPF ***.982.247-** ok");
    expect(mascararTexto("cpf=52998224725")).toBe("cpf=***.982.247-**");
    expect(mascararTexto("pedido 12345678901")).toBe("pedido 12345678901");
  });

  it("mascara CNPJ numérico, cru e alfanumérico", () => {
    expect(mascararTexto("CNPJ 11.222.333/0001-81")).toBe("CNPJ 11.***.***/****-81");
    expect(mascararTexto("cnpj 11222333000181")).toBe("cnpj 11.***.***/****-81");
    expect(mascararTexto("novo 12.ABC.345/01DE-35")).toBe("novo 12.***.***/****-35");
  });

  it("mascara e-mail mantendo o domínio", () => {
    expect(mascararTexto("contato: joao.silva+vip@empresa.com.br")).toBe("contato: j***@empresa.com.br");
  });

  it("mascara telefones BR em vários formatos", () => {
    expect(mascararTexto("(11) 98765-4321")).toBe("(11) *****-4321");
    expect(mascararTexto("+55 (21) 3333-4444")).toBe("(21) ****-4444");
    expect(mascararTexto("+55 11 98765 4321")).toBe("(11) *****-4321");
    expect(mascararTexto("whats 11987654321")).toBe("whats (11) *****-4321");
  });

  it("mascara cartão só quando passa no Luhn", () => {
    expect(luhnValido("4111111111111111")).toBe(true);
    expect(luhnValido("4111111111111112")).toBe(false);
    expect(mascararTexto("cartão 4111 1111 1111 1111")).toBe("cartão **** **** **** 1111");
    expect(mascararTexto("cartão 5555-5555-5555-4444")).toBe("cartão **** **** **** 4444");
    expect(mascararTexto("protocolo 4111111111111112")).toBe("protocolo 4111111111111112");
  });

  it("CEP é opcional e tipos podem ser ignorados", () => {
    expect(mascararTexto("CEP 01001-000")).toBe("CEP 01001-000");
    expect(mascararTexto("CEP 01001-000", { cep: true })).toBe("CEP 01***-***");
    expect(mascararTexto("a@b.com 529.982.247-25", { ignorar: ["email"] })).toBe("a@b.com ***.982.247-**");
  });

  it("redige chaves sensíveis em objetos profundos", () => {
    const entrada = {
      usuario: { email: "ana@x.com", senha: "123456", apiKey: "sk_live_x", perfil: { refresh_token: "r" } },
      headers: { Authorization: "Bearer abc", "x-api-key": "k", cookie: "s=1" },
      cartao: { numero: "4111111111111111", cvv: "123" },
      itens: [{ cpf: "529.982.247-25", pin: "0000" }],
      total: 100,
      ativo: true,
    };
    const saida = mascararObjeto(entrada);
    expect(saida).toEqual({
      usuario: { email: "a***@x.com", senha: REDACTED, apiKey: REDACTED, perfil: { refresh_token: REDACTED } },
      headers: { Authorization: REDACTED, "x-api-key": REDACTED, cookie: REDACTED },
      cartao: { numero: "**** **** **** 1111", cvv: REDACTED },
      itens: [{ cpf: "***.982.247-**", pin: REDACTED }],
      total: 100,
      ativo: true,
    });
    expect(entrada.usuario.senha).toBe("123456");
  });

  it("aceita chaves extras e trata ciclos, Date, Map e Error", () => {
    const obj: Record<string, unknown> = { nomeMae: "Maria", quando: new Date(0), mapa: new Map([["token", "x"], ["ok", "y"]]) };
    obj.eu = obj;
    const erro = new Error("falha para 529.982.247-25");
    const saida = mascararObjeto({ ...obj, erro }, { chavesSensiveis: ["nomemae", /^rg$/i] }) as Record<string, unknown>;
    expect(saida.nomeMae).toBe(REDACTED);
    expect((saida.quando as Date).getTime()).toBe(0);
    expect(saida.mapa).toEqual({ token: REDACTED, ok: "y" });
    expect(saida.eu).toMatchObject({ eu: "[Circular]" });
    expect(saida.erro).toMatchObject({ name: "Error", message: "falha para ***.982.247-**" });
  });

  it("limita a profundidade", () => {
    const fundo = { a: { b: { c: { d: 1 } } } };
    expect(mascararObjeto(fundo, { profundidadeMax: 2 })).toEqual({ a: { b: "[Profundidade máxima]" } });
  });
});
