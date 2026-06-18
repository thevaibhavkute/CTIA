import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

const AUTH_COOKIE_NAME = "ctia_access_token";
const LOGIN_PATH = "/login";

export function proxy(request: NextRequest) {
  const isAuthenticated = request.cookies.has(AUTH_COOKIE_NAME);
  const isLoginPage = request.nextUrl.pathname.startsWith(LOGIN_PATH);

  if (!isAuthenticated && !isLoginPage) {
    return NextResponse.redirect(new URL(LOGIN_PATH, request.url));
  }
  if (isAuthenticated && isLoginPage) {
    return NextResponse.redirect(new URL("/", request.url));
  }
  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
