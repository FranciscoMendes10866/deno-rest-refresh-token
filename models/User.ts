import { DataTypes, Model } from "https://deno.land/x/denodb/mod.ts";

import { RefreshToken } from "./RefreshToken.ts";

export class User extends Model {
  static table = "user";
  static timestamps = true;

  static fields = {
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true,
    },
    username: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false,
    },
  };

  static refreshTokens() {
    return this.hasMany(RefreshToken);
  }
}
