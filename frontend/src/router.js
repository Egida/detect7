import { createRouter, createWebHistory } from "vue-router";
import { useAuthStore } from "./stores/auth";
import LandingPage from "./views/LandingPage.vue";
import LoginPage from "./views/LoginPage.vue";
import RegisterPage from "./views/RegisterPage.vue";
import PanelPage from "./views/PanelPage.vue";

const routes = [
  { path: "/", name: "landing", component: LandingPage },
  { path: "/login", name: "login", component: LoginPage },
  { path: "/register", name: "register", component: RegisterPage },
  {
    path: "/app",
    name: "panel",
    component: PanelPage,
    meta: { requiresAuth: true },
  },
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

router.beforeEach((to) => {
  const auth = useAuthStore();
  if (to.meta.requiresAuth && !auth.isAuthenticated) {
    return { name: "login" };
  }
  if (["login", "register"].includes(to.name) && auth.isAuthenticated) {
    return { name: "panel" };
  }
  return true;
});

export default router;
