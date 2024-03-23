import { Request, Response } from "express";
import { validatePassword } from "../service/user.service";
import config from "config";
import { createSession, findSessions } from "../service/session.service";
import { signJwt } from "../utils/jwt.utils";

export async function createUserSessionHandler(req: Request, res: Response) {
  //Validate user's password

  // const user = await validatePassword(req.body);

  const { email, password } = req.body;
  const user = await validatePassword({ email, password });

  if (!user) {
    return res.status(401).send("Invalid email or password");
  }

  //Create a session
  const session = await createSession(user._id, req.get("user-agent") || "");

  console.log(`session: ${session}`);

  //Create an access token
  const accessToken = signJwt(
    { ...user, session: session._id },
    { expiresIn: config.get("accessTokenTtl") } //15 minutes
  );

  //Create a refresh token
  const refreshToken = signJwt(
    { ...user, session: session._id },
    { expiresIn: config.get("refreshTokenTtl") } //15 minutes
  );

  console.log(`accessToken: ${accessToken}, refreshToken: ${refreshToken}`);

  //Return access & refresh tokens
  return res.send({ accessToken, refreshToken });
}

export async function getUserSessionsHandler(req: Request, res: Response) {
  const userId = res.locals.user._id;

  const sessions = await findSessions({ user: userId, valid: true });

  return res.send(sessions);
}
