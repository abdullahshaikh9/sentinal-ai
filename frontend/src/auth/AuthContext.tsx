import { createContext, ReactNode, useContext, useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import { ApiError, getCurrentUser, login as loginRequest, logout as logoutRequest, register as registerRequest } from "../lib/api";
import type { LoginResult } from "../lib/api";
import type { User } from "../types";

type RegistrationPending = Awaited<ReturnType<typeof registerRequest>>;
type AuthContextValue = { user: User | null; loading: boolean; error: string | null; login: (email: string, password: string) => Promise<LoginResult>; register: (email: string, displayName: string, phoneNumber: string, password: string) => Promise<RegistrationPending>; completeAuthentication: (user: User) => void; logout: () => Promise<void> };
const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null); const [loading, setLoading] = useState(true); const [error, setError] = useState<string | null>(null);
  useEffect(() => { const expire = () => { setUser(null); setError("Your session expired. Please sign in again."); }; window.addEventListener("sentinel:session-expired", expire); getCurrentUser().then(setUser).catch((err: unknown) => { if (!(err instanceof ApiError && err.status === 401)) setError(err instanceof Error ? err.message : "Unable to load your session."); }).finally(() => setLoading(false)); return () => window.removeEventListener("sentinel:session-expired", expire); }, []);
  const login = async (email: string, password: string) => { setError(null); const result = await loginRequest(email, password); if ("user" in result) setUser(result.user); return result; };
  const register = async (email: string, displayName: string, phoneNumber: string, password: string) => { setError(null); return registerRequest(email, displayName, phoneNumber, password); };
  const completeAuthentication = (authenticatedUser: User) => { setError(null); setUser(authenticatedUser); };
  const logout = async () => { await logoutRequest(); setUser(null); };
  return <AuthContext.Provider value={{ user, loading, error, login, register, completeAuthentication, logout }}>{children}</AuthContext.Provider>;
}
export function useAuth(): AuthContextValue { const value = useContext(AuthContext); if (!value) throw new Error("useAuth must be used inside AuthProvider"); return value; }
export function RequireAuth({ children }: { children: ReactNode }) { const { user, loading } = useAuth(); if (loading) return <div className="flex min-h-screen items-center justify-center bg-mist text-sm text-slate-500">Loading your workspace…</div>; return user ? children : <Navigate to="/login" replace />; }
