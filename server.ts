import { Application, Router } from "https://deno.land/x/oak@v9.0.0/mod.ts";

import { db } from "./db/connect.ts";
import { userController } from "./controllers/User.ts";

const port = 3000;

const app = new Application<{ state: { userId: string } }>();
const router = new Router();

router.post("/auth/signup", userController.signUp);
router.post("/auth/signin", userController.signIn);
router.use(userController.authGuard);
router.get("/auth/current-user", userController.currentUser);
router.get("/auth/logout", userController.signOut);

app.use(router.allowedMethods());
app.use(router.routes());

app.addEventListener("listen", () => {
  console.log(`Listening on: localhost:${port}`);
});

await db.sync();
await app.listen({ port });
