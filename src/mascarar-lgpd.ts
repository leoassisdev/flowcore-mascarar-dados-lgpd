// mascarar-lgpd.ts · Criado por FlowCore Soluções LTDA · flowcoresolucoes.com.br/codigos · licença MIT
// Mascara dados pessoais antes de gravar log, mandar pro Sentry ou pra
// observabilidade (LGPD art. 46: segurança e minimização): CPF, CNPJ
// (inclusive alfanumérico), e-mail, telefone BR, cartão (só se passar no Luhn)
// e CEP opcional. Percorre objetos profundos e troca campos sensíveis pelo
// nome (senha, token, authorization, cookie, cvv...) por "[REDACTED]".
// Roda em Node 18+, Cloudflare Workers, Deno, Bun e no navegador.
// Zero dependências.
//
// Referências: Lei 13.709/2018 (LGPD), ISO/IEC 7812 (algoritmo de Luhn) e
// PCI DSS req. 3.4 (exibir no máximo os 4 últimos dígitos do cartão).

export const CRIADO_POR = "Criado por FlowCore Soluções LTDA";

export const REDACTED = "[REDACTED]";

export type OpcoesMascara = {
  /** Mascarar CEP (padrão false: CEP sozinho raramente identifica alguém). */
  cep?: boolean;
  /** Desliga tipos específicos. */
  ignorar?: Array<"cpf" | "cnpj" | "email" | "telefone" | "cartao">;
};

export type OpcoesObjeto = OpcoesMascara & {
  /** Chaves extras a redigir por completo (texto exato, sem diferenciar maiúsculas, ou RegExp). */
  chavesSensiveis?: Array<string | RegExp>;
  /** Profundidade máxima percorrida. Padrão 20. */
  profundidadeMax?: number;
};

/** Algoritmo de Luhn (mod 10) usado em cartões. */
export function luhnValido(digitos: string): boolean {
  if (!/^\d{12,19}$/.test(digitos)) return false;
  let soma = 0;
  let dobrar = false;
  for (let i = digitos.length - 1; i >= 0; i--) {
    let n = Number(digitos[i]);
    if (dobrar) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    soma += n;
    dobrar = !dobrar;
  }
  return soma % 10 === 0;
}

function cpfValido(d: string): boolean {
  if (!/^\d{11}$/.test(d) || /^(\d)\1{10}$/.test(d)) return false;
  const dv = (n: number) => {
    let s = 0;
    for (let i = 0; i < n; i++) s += Number(d[i]) * (n + 1 - i);
    const r = (s * 10) % 11;
    return r === 10 ? 0 : r;
  };
  return dv(9) === Number(d[9]) && dv(10) === Number(d[10]);
}

function cnpjValido(c: string): boolean {
  if (!/^[0-9A-Z]{12}\d{2}$/.test(c) || /^(\d)\1{13}$/.test(c)) return false;
  const dv = (base: string) => {
    let s = 0;
    let p = 2;
    for (let i = base.length - 1; i >= 0; i--) {
      s += (base.charCodeAt(i) - 48) * p;
      p = p === 9 ? 2 : p + 1;
    }
    const r = s % 11;
    return r < 2 ? 0 : 11 - r;
  };
  const d1 = dv(c.slice(0, 12));
  return `${d1}${dv(c.slice(0, 12) + d1)}` === c.slice(12);
}

const mCpf = (d: string) => `***.${d.slice(3, 6)}.${d.slice(6, 9)}-**`;
const mCnpj = (c: string) => `${c.slice(0, 2)}.***.***/****-${c.slice(12)}`;
const mCartao = (d: string) => `**** **** **** ${d.slice(-4)}`;
const mTelefone = (ddd: string, numero: string) => `(${ddd}) ${"*".repeat(numero.length - 4)}-${numero.slice(-4)}`;

/** Mascara dados pessoais dentro de um texto livre. */
export function mascararTexto(texto: string, opcoes: OpcoesMascara = {}): string {
  const ign = new Set(opcoes.ignorar ?? []);
  let s = texto;

  if (!ign.has("email"))
    s = s.replace(/\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g, (_m, primeiro, dominio) => `${primeiro}***@${dominio}`);

  if (!ign.has("cnpj"))
    s = s.replace(/\b[0-9A-Za-z]{2}\.[0-9A-Za-z]{3}\.[0-9A-Za-z]{3}\/[0-9A-Za-z]{4}-\d{2}\b/g, (m) => {
      const c = m.toUpperCase().replace(/[^0-9A-Z]/g, "");
      return cnpjValido(c) ? mCnpj(c) : m;
    });

  if (!ign.has("cpf")) s = s.replace(/\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g, (m) => mCpf(m.replace(/\D/g, "")));

  if (!ign.has("telefone"))
    s = s.replace(/(?:\+?55\s?)?\((\d{2})\)\s?(9?\d{4})[-\s]?(\d{4})\b/g, (_m, ddd, a, b) => mTelefone(ddd, a + b));

  if (!ign.has("telefone"))
    s = s.replace(/\+55\s?(\d{2})\s?(9?\d{4})[-\s]?(\d{4})\b/g, (_m, ddd, a, b) => mTelefone(ddd, a + b));

  // Sequências longas de dígitos (com espaço/hífen): cartão (Luhn) ou CNPJ cru.
  s = s.replace(/\b\d(?:[ -]?\d){12,18}\b/g, (m) => {
    const d = m.replace(/\D/g, "");
    if (d.length === 14 && !ign.has("cnpj") && cnpjValido(d)) return mCnpj(d);
    if (!ign.has("cartao") && luhnValido(d)) return mCartao(d);
    return m;
  });

  // 11 dígitos crus: CPF se o DV bate; senão celular (3º dígito 9).
  s = s.replace(/\b\d{11}\b/g, (d) => {
    if (!ign.has("cpf") && cpfValido(d)) return mCpf(d);
    if (!ign.has("telefone") && d[2] === "9") return mTelefone(d.slice(0, 2), d.slice(2));
    return d;
  });

  if (opcoes.cep) s = s.replace(/\b(\d{2})\d{3}-?\d{3}\b/g, (_m, ini) => `${ini}***-***`);

  return s;
}

const PALAVRAS_SENSIVEIS = [
  "senha",
  "password",
  "passwd",
  "secret",
  "segredo",
  "token",
  "authorization",
  "apikey",
  "cookie",
  "cvv",
  "cvc",
  "privatekey",
  "credential",
  "credencial",
];

function chaveSensivel(chave: string, extras: Array<string | RegExp>): boolean {
  const k = chave.toLowerCase().replace(/[-_\s]/g, "");
  if (k === "pin" || k === "pwd") return true;
  if (PALAVRAS_SENSIVEIS.some((p) => k.includes(p))) return true;
  return extras.some((e) => (typeof e === "string" ? e.toLowerCase() === chave.toLowerCase() : e.test(chave)));
}

/**
 * Devolve uma CÓPIA do valor com dados pessoais mascarados. Lida com arrays,
 * referências circulares ("[Circular]"), Date, Map/Set e Error.
 */
export function mascararObjeto<T>(valor: T, opcoes: OpcoesObjeto = {}): T {
  const extras = opcoes.chavesSensiveis ?? [];
  const max = opcoes.profundidadeMax ?? 20;
  const vistos = new WeakSet<object>();

  const andar = (v: unknown, nivel: number): unknown => {
    if (typeof v === "string") return mascararTexto(v, opcoes);
    if (v === null || typeof v !== "object") return v;
    if (v instanceof Date) return new Date(v.getTime());
    if (vistos.has(v)) return "[Circular]";
    if (nivel >= max) return "[Profundidade máxima]";
    vistos.add(v);
    try {
      if (Array.isArray(v)) return v.map((x) => andar(x, nivel + 1));
      if (v instanceof Map) return Object.fromEntries([...v].map(([k, x]) => [String(k), chaveSensivel(String(k), extras) ? REDACTED : andar(x, nivel + 1)]));
      if (v instanceof Set) return [...v].map((x) => andar(x, nivel + 1));
      const fonte: Record<string, unknown> =
        v instanceof Error ? { name: v.name, message: v.message, ...(v as unknown as Record<string, unknown>) } : (v as Record<string, unknown>);
      const out: Record<string, unknown> = {};
      for (const k of Object.keys(fonte)) out[k] = chaveSensivel(k, extras) ? REDACTED : andar(fonte[k], nivel + 1);
      return out;
    } finally {
      vistos.delete(v);
    }
  };
  return andar(valor, 0) as T;
}
