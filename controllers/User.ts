import { Context, RouterMiddleware } from "https://deno.land/x/oak@v9.0.0/mod.ts";
import * as bcrypt from "https://deno.land/x/bcrypt/mod.ts";
import { create, verify } from "https://deno.land/x/djwt/mod.ts";
import { nanoid } from "https://deno.land/x/nanoid/mod.ts";
import dayjs from "https://deno.land/x/deno_dayjs@v0.2.2/mod.ts";

import { User } from "../models/User.ts";
import { RefreshToken } from "../models/RefreshToken.ts";

const key = await crypto.subtle.generateKey(
  { name: "HMAC", hash: "SHA-512" },
  true,
  ["sign", "verify"],
);

class UserController {
  public signUp = async (ctx: Context) => {
    const { value } = ctx.request.body({ type: "json" });
    const { username, password } = await value;

    if (!username || !password) {
      ctx.response.status = 400;
      ctx.response.body = {
        error: "Username and password are required.",
      };
      return;
    }

    const found = await User.where("username", username).first();

    if (found) {
      ctx.response.status = 404;
      ctx.response.body = {
        error: "Username already taken.",
      };
      return;
    }

    const hashedPassword = await bcrypt.hash(password);

    const newUser = new User();
    newUser.username = username;
    newUser.password = hashedPassword;

    const result = await newUser.save();

    ctx.response.body = { result };
  };

  public signIn = async (ctx: Context) => {
    const { value } = ctx.request.body({ type: "json" });
    const { username, password } = await value;

    if (!username || !password) {
      ctx.response.status = 400;
      ctx.response.body = {
        error: "Username and password are required.",
      };
      return;
    }

    const found = await User.where("username", username).first();

    if (!found) {
      ctx.response.status = 404;
      ctx.response.body = {
        error: "User not found.",
      };
      return;
    }

    const isPasswordValid = await bcrypt.compare(
      password,
      found.password as string,
    );

    if (!isPasswordValid) {
      ctx.response.status = 401;
      ctx.response.body = {
        error: "Invalid password.",
      };
      return;
    }

    const userId = found.id as string

    const accessToken = await create({ alg: "HS512", typ: "JWT" }, {
      userId,
    }, key);

    const refreshToken = this.createRefreshToken();

    const newRefreshToken = new RefreshToken()
    newRefreshToken.token = refreshToken.token
    newRefreshToken.expiresAt = refreshToken.expiresAt
    newRefreshToken.userId = userId

    const result = await newRefreshToken.save()

    if (!result.token) {
      ctx.response.status = 500;
      ctx.response.body = {
        error: "Error while creating session.",
      };
      return;
    }

    ctx.response.body = {
      session: {
        accessToken,
        refreshToken: result.token,
      },
      user: {
        username,
      },
    };
  };

  public authGuard: RouterMiddleware = async (ctx, next) => {
    const authorization = ctx.request.headers.get("Authorization")

    if (!authorization) {
      ctx.response.status = 401;
      ctx.response.body = {
        error: "Authorization header is required.",
      }
      return
    }

    const isValid = authorization.startsWith("Bearer ");

    if (!isValid) {
      ctx.response.status = 401;
      ctx.response.body = {
        error: "Invalid authorization header.",
      }
      return
    }

    const token = authorization.replace("Bearer ", "").trim();

    try {
      const payload = await verify(token, key);
      ctx.state = { userId: payload.id }
    } catch {
      ctx.response.status = 401;
      ctx.response.body = {
        error: "Invalid token.",
      }
      return
    }

    await next()
  }

  public currentUser = async (ctx: Context) => {
    const userId = ctx.state.userId as string
    const result = await User.where("id", userId).first()
    ctx.response.body = { currentUser: result }
  }

  public signOut = async (ctx: Context) => {
    const { value } = ctx.request.body({ type: "json" });
    const { refreshToken } = await value;

    if (!refreshToken) {
      ctx.response.status = 400;
      ctx.response.body = {
        error: "Session is required.",
      };
      return;
    }

    const found = await RefreshToken.where("token", refreshToken).first()

    if (!found.token) {
      ctx.response.status = 401;
      ctx.response.body = {
        error: "Session not found.",
      };
      return;
    }

    await RefreshToken.deleteById(found.id as number)

    ctx.response.status = 204
    ctx.response.body = "Successfully logged out."
  }

  public tokenRefresh = async (ctx: Context) => {
    const { value } = ctx.request.body({ type: "json" });
    const { refreshToken } = await value;

    if (!refreshToken) {
      ctx.response.status = 400;
      ctx.response.body = {
        error: "Session is required.",
      };
      return;
    }

    const found = await RefreshToken.where("token", refreshToken).first()

    if (!found.token) {
      ctx.response.status = 401;
      ctx.response.body = {
        error: "Session not found.",
      };
      return;
    }

    const isExpired = this.isRefreshTokenExpired(found.expiresAt as number)

    if (isExpired) {
      await RefreshToken.deleteById(found.id as number)

      ctx.response.status = 500;
      ctx.response.body = {
        error: "Session expired.",
      };
      return;
    }

    await RefreshToken.deleteById(found.id as number)

    const userId = found.userId as string

    const accessToken = await create({ alg: "HS512", typ: "JWT" }, {
      userId,
    }, key);

    const createdRefreshToken = this.createRefreshToken();

    const newRefreshToken = new RefreshToken()
    newRefreshToken.token = createdRefreshToken.token
    newRefreshToken.expiresAt = createdRefreshToken.expiresAt
    newRefreshToken.userId = userId

    const result = await newRefreshToken.save()

    if (!result.token) {
      ctx.response.status = 500;
      ctx.response.body = {
        error: "Error while creating new session.",
      };
      return;
    }

    ctx.response.body = {
      accessToken,
      refreshToken: result.token,
    };
  }

  /**
   * Utils
   */

  private createRefreshToken = () => {
    return {
      token: nanoid(),
      expiresAt: dayjs().add(7, "days").unix(),
    };
  };

  private isRefreshTokenExpired = (expiresAt: number): boolean => {
    return dayjs().isAfter(dayjs.unix(expiresAt));
  };
}

export const userController = new UserController();
