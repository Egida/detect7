<template>
  <div class="card shadow-sm">
    <div class="card-body">
      <h5 class="card-title">Add domain</h5>
      <form @submit.prevent="$emit('submit')">
        <label class="form-label">Domain name</label>
        <input
          :value="modelValue"
          class="form-control"
          placeholder="example.com"
          required
          @input="$emit('update:modelValue', $event.target.value)"
        />
        <button class="btn btn-primary mt-3 w-100" :disabled="loading">
          {{ loading ? "Adding..." : "Add domain" }}
        </button>
      </form>
      <p class="small text-secondary mt-3 mb-0">
        Add multiple domains and verify ownership to activate analytics.
      </p>
    </div>
  </div>
</template>

<script setup>
defineProps({
  modelValue: {
    type: String,
    default: "",
  },
  loading: {
    type: Boolean,
    default: false,
  },
});

defineEmits(["update:modelValue", "submit"]);
</script>
