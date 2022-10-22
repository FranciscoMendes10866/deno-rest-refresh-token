import { Context } from "https://deno.land/x/oak@v9.0.0/mod.ts";
import * as bcrypt from "https://deno.land/x/bcrypt/mod.ts";
import { create } from "https://deno.land/x/djwt/mod.ts";
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
  public signup = async (ctx: Context) => {
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

  public signin = async (ctx: Context) => {
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
        refreshToken: {
          token: result.token,
          expiresAt: result.expiresAt
        },
      },
      user: {
        username,
      },
    };
  };

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
