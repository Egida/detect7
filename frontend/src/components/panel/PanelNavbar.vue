<template>
  <nav class="navbar navbar-expand-lg bg-white border-bottom">
    <div class="container">
      <span class="navbar-brand fw-semibold">Detect7 Cloud</span>
      <div class="ms-auto d-flex align-items-center gap-3">
        <span class="text-secondary small">{{ userEmail }}</span>
        <button class="btn btn-outline-secondary btn-sm" @click="$emit('logout')">Logout</button>
      </div>
    </div>
  </nav>
</template>

<script setup>
defineProps({
  userEmail: {
    type: String,
    default: "",
  },
});

defineEmits(["logout"]);
</script>
