import { DataTypes, Model } from "https://deno.land/x/denodb/mod.ts";

import { User } from "./User.ts";

export class RefreshToken extends Model {
  static table = "refresh_tokens";
  static timestamps = true;

  static fields = {
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true,
    },
    token: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    expiresAt: {
      type: DataTypes.INTEGER,
      allowNull: false,
    },
  };

  static user() {
    return this.hasOne(User);
  }
}
