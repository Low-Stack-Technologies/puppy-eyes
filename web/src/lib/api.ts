export type Address = {
  id: string;
  email: string;
  name: string;
  domain: string;
};

export type AuthMe = {
  userId: string;
  username: string;
  isAdmin: boolean;
  activeAddressId: string;
  accessibleAddress: Address[];
};

export type Mailbox = {
  id: string;
  name: string;
  type: string;
  addressId: string;
  uidNext: number;
};

export type MessageSummary = {
  id: string;
  uid: number;
  sender: string;
  recipients: string[];
  subject: string;
  flags: string[];
  createdAt: string;
};

export type MessageDetail = {
  id: string;
  uid: number;
  sender: string;
  recipients: string[];
  flags: string[];
  createdAt: string;
  body: string;
};

export type SettingsUser = {
  id: string;
  username: string;
  isAdmin: boolean;
  createdAt: string;
};

export type SettingsDomain = {
  id: string;
  name: string;
  smtpDomain: string;
  createdAt: string;
};

export type SettingsAddress = {
  id: string;
  name: string;
  domainId: string;
  domainName: string;
  createdAt: string;
};

export type SettingsAccess = {
  userId: string;
  username: string;
  addressId: string;
  addressName: string;
  domainName: string;
};

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
    ...init,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Request failed: ${res.status}`);
  }

  return (await res.json()) as T;
}

export async function login(username: string, password: string): Promise<void> {
  await request("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
}

export async function logout(): Promise<void> {
  await request("/api/auth/logout", { method: "POST" });
}

export async function authMe(): Promise<AuthMe> {
  return request<AuthMe>("/api/auth/me");
}

export async function setActiveAddress(addressId: string): Promise<void> {
  await request("/api/user/active-address", {
    method: "PUT",
    body: JSON.stringify({ addressId }),
  });
}

export async function listMailboxes(addressId: string): Promise<Mailbox[]> {
  const payload = await request<{ items: Mailbox[] }>(`/api/mailboxes?addressId=${encodeURIComponent(addressId)}`);
  return payload.items;
}

export async function listMessages(addressId: string, mailboxId: string, cursor?: number): Promise<{ items: MessageSummary[]; nextCursor: number; hasMore: boolean; }> {
  const search = new URLSearchParams({ addressId, mailboxId, limit: "50" });
  if (cursor && cursor > 0) {
    search.set("cursor", String(cursor));
  }
  return request(`/api/messages?${search.toString()}`);
}

export async function getMessage(addressId: string, mailboxId: string, messageId: string): Promise<MessageDetail> {
  return request(`/api/messages/${encodeURIComponent(messageId)}?addressId=${encodeURIComponent(addressId)}&mailboxId=${encodeURIComponent(mailboxId)}`);
}

export async function sendMessage(payload: {
  fromAddressId: string;
  to: string[];
  cc: string[];
  bcc: string[];
  subject: string;
  textBody: string;
  htmlBody: string;
}): Promise<void> {
  await request("/api/messages", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function updateFlags(messageId: string, mailboxId: string, addFlags: string[], removeFlags: string[]): Promise<void> {
  await request(`/api/messages/${encodeURIComponent(messageId)}/flags`, {
    method: "POST",
    body: JSON.stringify({ mailboxId, addFlags, removeFlags }),
  });
}

export async function moveMessage(messageId: string, fromMailboxId: string, toMailboxId: string): Promise<void> {
  await request(`/api/messages/${encodeURIComponent(messageId)}/move`, {
    method: "POST",
    body: JSON.stringify({ fromMailboxId, toMailboxId }),
  });
}

export async function deleteMessage(messageId: string, mailboxId: string): Promise<void> {
  await request(`/api/messages/${encodeURIComponent(messageId)}?mailboxId=${encodeURIComponent(mailboxId)}`, {
    method: "DELETE",
  });
}

export async function listSettings(path: "users" | "domains" | "addresses" | "mailboxes" | "access"): Promise<{ items: unknown[] }> {
  return request(`/api/settings/${path}`);
}

function pickString(v: Record<string, unknown>, ...keys: string[]): string {
  for (const key of keys) {
    const value = v[key];
    if (typeof value === "string") return value;
  }
  return "";
}

function pickBool(v: Record<string, unknown>, ...keys: string[]): boolean {
  for (const key of keys) {
    const value = v[key];
    if (typeof value === "boolean") return value;
  }
  return false;
}

function normalizeUser(v: unknown): SettingsUser {
  const row = (v ?? {}) as Record<string, unknown>;
  return {
    id: pickString(row, "id", "ID"),
    username: pickString(row, "username", "Username"),
    isAdmin: pickBool(row, "isAdmin", "IsAdmin"),
    createdAt: pickString(row, "createdAt", "CreatedAt"),
  };
}

function normalizeDomain(v: unknown): SettingsDomain {
  const row = (v ?? {}) as Record<string, unknown>;
  return {
    id: pickString(row, "id", "ID"),
    name: pickString(row, "name", "Name"),
    smtpDomain: pickString(row, "smtpDomain", "SmtpDomain"),
    createdAt: pickString(row, "createdAt", "CreatedAt"),
  };
}

function normalizeAddress(v: unknown): SettingsAddress {
  const row = (v ?? {}) as Record<string, unknown>;
  return {
    id: pickString(row, "id", "ID"),
    name: pickString(row, "name", "Name"),
    domainId: pickString(row, "domainId", "DomainID", "domain", "Domain"),
    domainName: pickString(row, "domainName", "DomainName"),
    createdAt: pickString(row, "createdAt", "CreatedAt"),
  };
}

function normalizeAccess(v: unknown): SettingsAccess {
  const row = (v ?? {}) as Record<string, unknown>;
  return {
    userId: pickString(row, "userId", "UserID"),
    username: pickString(row, "username", "Username"),
    addressId: pickString(row, "addressId", "AddressID"),
    addressName: pickString(row, "addressName", "AddressName"),
    domainName: pickString(row, "domainName", "DomainName"),
  };
}

export async function listUsers(): Promise<SettingsUser[]> {
  const payload = await request<{ items: unknown[] }>("/api/settings/users");
  return payload.items.map(normalizeUser);
}

export async function createUser(payload: { username: string; password: string; isAdmin: boolean }): Promise<void> {
  await request("/api/settings/users", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function updateUser(id: string, payload: { username: string; password?: string; isAdmin: boolean }): Promise<void> {
  await request(`/api/settings/users/${encodeURIComponent(id)}`, {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export async function deleteUser(id: string): Promise<void> {
  await request(`/api/settings/users/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

export async function listDomains(): Promise<SettingsDomain[]> {
  const payload = await request<{ items: unknown[] }>("/api/settings/domains");
  return payload.items.map(normalizeDomain);
}

export async function createDomain(payload: { name: string; smtpDomain: string }): Promise<void> {
  await request("/api/settings/domains", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function updateDomain(id: string, payload: { name: string; smtpDomain: string }): Promise<void> {
  await request(`/api/settings/domains/${encodeURIComponent(id)}`, {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export async function deleteDomain(id: string): Promise<void> {
  await request(`/api/settings/domains/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

export async function listAddresses(): Promise<SettingsAddress[]> {
  const payload = await request<{ items: unknown[] }>("/api/settings/addresses");
  return payload.items.map(normalizeAddress);
}

export async function createAddress(payload: { name: string; domainId: string }): Promise<void> {
  await request("/api/settings/addresses", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function updateAddress(id: string, payload: { name: string; domainId: string }): Promise<void> {
  await request(`/api/settings/addresses/${encodeURIComponent(id)}`, {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export async function deleteAddress(id: string): Promise<void> {
  await request(`/api/settings/addresses/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

export async function listAccess(): Promise<SettingsAccess[]> {
  const payload = await request<{ items: unknown[] }>("/api/settings/access");
  return payload.items.map(normalizeAccess);
}

export async function createAccess(payload: { userId: string; addressId: string }): Promise<void> {
  await request("/api/settings/access", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function deleteAccess(userId: string, addressId: string): Promise<void> {
  await request(`/api/settings/access/${encodeURIComponent(userId)}/${encodeURIComponent(addressId)}`, {
    method: "DELETE",
  });
}
