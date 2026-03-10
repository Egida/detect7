<template>
  <nav class="navbar navbar-expand-lg border-bottom">
    <div class="container">
      <span class="navbar-brand fw-semibold">Detect7 Cloud</span>
      <div class="ms-auto d-flex align-items-center gap-3">
        <div class="d-flex gap-1">
          <button
            v-for="r in ranges"
            :key="r"
            class="time-range-btn"
            :class="{ active: modelRange === r }"
            @click="$emit('update:modelRange', r)"
          >{{ r }}</button>
        </div>
        <button class="theme-toggle" @click="toggleTheme" :title="isDark ? 'Switch to light' : 'Switch to dark'">
          <i :class="isDark ? 'bi bi-sun-fill' : 'bi bi-moon-fill'"></i>
        </button>
        <span class="text-secondary small">{{ userEmail }}</span>
        <button class="btn btn-outline-secondary btn-sm" @click="$emit('logout')">Logout</button>
      </div>
    </div>
  </nav>
</template>

<script setup>
import { ref, onMounted } from "vue";

defineProps({
  userEmail: { type: String, default: "" },
  modelRange: { type: String, default: "30m" },
});
defineEmits(["logout", "update:modelRange"]);

const ranges = ["5m", "30m", "1h", "6h", "24h", "7d"];
const isDark = ref(false);

const applyTheme = (dark) => {
  document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
  isDark.value = dark;
  localStorage.setItem("detect7-theme", dark ? "dark" : "light");
};

const toggleTheme = () => applyTheme(!isDark.value);

onMounted(() => {
  const saved = localStorage.getItem("detect7-theme");
  applyTheme(saved === "dark");
});
</script>
