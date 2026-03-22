import { NextResponse } from "next/server";
import { createServerClient } from "../../../lib/supabase";
import { cookies } from "next/headers";

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const code = searchParams.get("code");
  const origin = new URL(request.url).origin;

  if (code) {
    const cookieStore = await cookies();
    const supabase = createServerClient(cookieStore);

    const { error } = await supabase.auth.exchangeCodeForSession(code);

    if (!error) {
      // Auto-create organization record on first sign-in
      const {
        data: { user }
      } = await supabase.auth.getUser();

      if (user) {
        const { data: existingOrg } = await supabase
          .from("organizations")
          .select("id")
          .eq("owner_id", user.id)
          .maybeSingle();

        if (!existingOrg) {
          const orgName =
            user.user_metadata?.user_name ??
            user.user_metadata?.full_name ??
            user.email?.split("@")[0] ??
            "My Organization";

          await supabase.from("organizations").insert({
            owner_id: user.id,
            name: `${orgName}'s org`,
            slug: `${orgName}`.toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 48)
          });
        }
      }

      return NextResponse.redirect(`${origin}/dashboard`);
    }
  }

  // Auth error — redirect to login with error indicator
  return NextResponse.redirect(`${origin}/login?error=auth`);
}
