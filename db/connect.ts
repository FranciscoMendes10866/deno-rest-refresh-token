import {
  Database,
  Relationships,
  SQLite3Connector,
} from "https://deno.land/x/denodb/mod.ts";

import { User } from "../models/User.ts";
import { RefreshToken } from "../models/RefreshToken.ts";

const connector = new SQLite3Connector({
  filepath: "./dev.sqlite",
});

export const db = new Database(connector);

Relationships.belongsTo(RefreshToken, User);
db.link([User, RefreshToken]);
