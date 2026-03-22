import Link from "next/link";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { createServerClient } from "../../lib/supabase";
import { getDashboardSnapshot } from "../../lib/site-data";

const navItems = [
  { href: "/dashboard", label: "Overview" },
  { href: "/dashboard/watchlists", label: "Watchlists" },
  { href: "/dashboard/billing", label: "Billing" },
  { href: "/dashboard/settings", label: "Settings" }
];

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  const cookieStore = await cookies();
  const supabase = createServerClient(cookieStore);

  const {
    data: { user }
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  const snapshot = await getDashboardSnapshot();

  return (
    <div className="dashboard-layout">
      <aside className="dashboard-sidebar">
        <div className="dashboard-sidebar__hero">
          <p className="eyebrow">Authenticated workspace</p>
          <h1>Org dashboard</h1>
          <p>Team-level visibility for repositories, package watchlists, billing, and settings.</p>
          <p className="dashboard-user-info">
            Signed in as <strong>{user.email ?? user.user_metadata?.user_name ?? "user"}</strong>
          </p>
        </div>

        <nav className="dashboard-nav">
          {navItems.map((item) => (
            <Link key={item.href} href={item.href} className="dashboard-nav__link">
              {item.label}
            </Link>
          ))}
        </nav>

        <div className="dashboard-sidebar__panel">
          <span className={`status-pill status-pill--${snapshot.mode === "live" ? "healthy" : "watch"}`}>
            {snapshot.mode === "live" ? "Live API mode" : "Demo data mode"}
          </span>
          <p>{snapshot.metrics[0]?.value} repositories tracked</p>
          <p>{snapshot.metrics[2]?.value} open reviews</p>
        </div>
      </aside>

      <section className="dashboard-content">{children}</section>
    </div>
  );
}
