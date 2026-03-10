import { defineStore } from "pinia";
import api from "../api";

export const useAuthStore = defineStore("auth", {
  state: () => ({
    token: localStorage.getItem("detect7_token") || "",
    userEmail: localStorage.getItem("detect7_email") || "",
    loading: false,
    error: "",
  }),
  getters: {
    isAuthenticated: (state) => Boolean(state.token),
  },
  actions: {
    setSession(token, email) {
      this.token = token;
      this.userEmail = email;
      localStorage.setItem("detect7_token", token);
      localStorage.setItem("detect7_email", email);
    },
    clearSession() {
      this.token = "";
      this.userEmail = "";
      localStorage.removeItem("detect7_token");
      localStorage.removeItem("detect7_email");
    },
    async register(email, password) {
      this.loading = true;
      this.error = "";
      try {
        await api.post("/auth/register", { email, password });
      } catch (err) {
        this.error = err?.response?.data?.detail || "Registration failed";
        throw err;
      } finally {
        this.loading = false;
      }
    },
    async login(email, password) {
      this.loading = true;
      this.error = "";
      try {
        const { data } = await api.post("/auth/login", { email, password });
        this.setSession(data.access_token, email);
      } catch (err) {
        this.error = err?.response?.data?.detail || "Login failed";
        throw err;
      } finally {
        this.loading = false;
      }
    },
    logout() {
      this.clearSession();
    },
  },
});
