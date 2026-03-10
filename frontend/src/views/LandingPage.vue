<template>
  <div class="hero-bg text-white min-vh-100 d-flex flex-column">
    <nav class="container py-4 d-flex justify-content-between align-items-center">
      <h3 class="m-0">Detect7 Cloud</h3>
      <div class="d-flex gap-2">
        <router-link to="/login" class="btn btn-outline-light">Sign in</router-link>
        <router-link to="/register" class="btn btn-light">Start free</router-link>
      </div>
    </nav>

    <section class="container py-5 my-auto">
      <div class="row align-items-center g-5">
        <div class="col-lg-7">
          <span class="badge text-bg-info mb-3">Layer 7 DDoS Detection</span>
          <h1 class="display-5 fw-bold mb-3">Turn Nginx traffic into actionable attack intelligence</h1>
          <p class="lead text-white-50">
            Detect7 Cloud processes access logs in near real time, applies machine-learning
            detection, and gives security teams a clean dashboard to spot anomalies quickly.
          </p>
          <div class="d-flex gap-3 mt-4">
            <router-link to="/register" class="btn btn-primary btn-lg">Create account</router-link>
            <a href="#features" class="btn btn-outline-light btn-lg">View features</a>
          </div>
        </div>
        <div class="col-lg-5">
          <div class="card bg-dark border-secondary text-white shadow">
            <div class="card-body">
              <h5>What you get</h5>
              <ul class="mb-0">
                <li>Near real-time log ingestion and normalization</li>
                <li>ML-based anomaly and DDoS pattern detection</li>
                <li>Operational dashboard inspired by your existing Graylog views</li>
                <li>Multi-domain onboarding and ownership verification</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </section>
  </div>

  <section id="features" class="container py-5">
    <div class="row g-4">
      <div class="col-md-4" v-for="item in features" :key="item.title">
        <div class="card h-100 border-0 shadow-sm">
          <div class="card-body">
            <h5>{{ item.title }}</h5>
            <p class="text-secondary mb-0">{{ item.text }}</p>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>

<script setup>
const features = [
  {
    title: "Built for Nginx",
    text: "Forward logs from each domain to a single collector endpoint using provided snippets.",
  },
  {
    title: "Security-first onboarding",
    text: "Verify ownership by hosting a one-time TXT file in your domain root.",
  },
  {
    title: "Simple dashboard",
    text: "Track request volume, suspicious events, and top sources in one panel.",
  },
];
</script>
