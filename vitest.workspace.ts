import { fileURLToPath } from "node:url";
import { defineWorkspace } from "vitest/config";

// Test against the firebase-auth source, not its built dist.
const firebaseAuthSource = fileURLToPath(
  new URL("./packages/firebase-auth/src/index.ts", import.meta.url),
);

export default defineWorkspace([
  {
    resolve: {
      alias: { "@fiboup/firebase-auth": firebaseAuthSource },
    },
    test: {
      name: "H3 Firebase Auth",
      environment: "node",
      include: ["packages/h3-firebase-auth/**/*.test.ts"],
    },
  },
  {
    test: {
      name: "Firebase Auth",
      environment: "node",
      include: ["packages/firebase-auth/**/*.test.ts"],
    },
  },
  {
    resolve: {
      alias: { "@fiboup/firebase-auth": firebaseAuthSource },
    },
    test: {
      name: "Hono Firebase Auth",
      environment: "node",
      include: ["packages/hono-firebase-auth/**/*.test.ts"],
    },
  },
]);
