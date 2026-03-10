<template>
  <div class="container py-5">
    <div class="row justify-content-center">
      <div class="col-md-6 col-lg-4">
        <div class="card shadow-sm">
          <div class="card-body p-4">
            <h3 class="mb-3">Sign in</h3>
            <p class="text-secondary">Access your Detect7 dashboard.</p>
            <form @submit.prevent="submit">
              <div class="mb-3">
                <label class="form-label">Email</label>
                <input v-model="email" type="email" class="form-control" required />
              </div>
              <div class="mb-3">
                <label class="form-label">Password</label>
                <input v-model="password" type="password" class="form-control" required />
              </div>
              <div v-if="auth.error" class="alert alert-danger py-2">{{ auth.error }}</div>
              <button class="btn btn-primary w-100" :disabled="auth.loading">
                {{ auth.loading ? "Signing in..." : "Sign in" }}
              </button>
            </form>
            <p class="small mt-3 mb-0">
              No account?
              <router-link to="/register">Create one</router-link>
            </p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from "vue";
import { useRouter } from "vue-router";
import { useAuthStore } from "../stores/auth";

const auth = useAuthStore();
const router = useRouter();
const email = ref("");
const password = ref("");

const submit = async () => {
  try {
    await auth.login(email.value, password.value);
    router.push("/app");
  } catch (_err) {
    // handled via store state
  }
};
</script>
