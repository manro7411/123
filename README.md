import { createContext, useState, useEffect, type ReactNode } from "react";
import { jwtDecode } from "jwt-decode";

interface User {
    upn?: string;
    name?: string;
    email?: string;
    groups?: string[];
    role?: string;
    exp?: number;
    [key: string]: unknown;
}

interface AuthContextType {
    token: string | null;
    user: User | null;
    login: (token: string) => void;
    logout: () => void;
}

export const AuthContext = createContext<AuthContextType>({
    token: null,
    user: null,
    login: () => {},
    logout: () => {},
});

function getCookie(name:string){
      const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop()?.split(';').shift() || null;
    return null;
}

export function AuthProvider({ children }: { children: ReactNode }) {
    const [token, setToken] = useState<string | null>(null);
    const [user, setUser] = useState<User | null>(null);

    const decodeAndSetUser = (jwt: string) => {
        try {
            const decoded = jwtDecode<User>(jwt);
            setUser(decoded);
        } catch (e) {
            console.error("❌ Failed to decode token:", e);
            logout(); 
        }
    };

    useEffect(()=>{
        if (!token) {
            const cookieToken = getCookie("access_token");
            if (cookieToken) {
                setToken(cookieToken)
                
            }
            
        }
    })

    useEffect(() => {
        if (token) {
            try {
                const decoded = jwtDecode<User>(token);
                const now = Date.now() / 1000;
                if (decoded.exp && decoded.exp > now) {
                    setUser(decoded);
                } else {
                    logout();
                }
            } catch {
                logout();
            }
        }
    }, [token]);

    const login = (accessToken: string) => {
        // sessionStorage.setItem("accessToken",accessToken);
        // document.cookie = `token=${token}; path=/; SameSite=Strict; Secure`
        setToken(accessToken);
        decodeAndSetUser(accessToken);
    };

    const logout = () => {
        // sessionStorage.removeItem("token");
        // document.cookie = `token=${token}; path=/; SameSite=Strict; Secure`
        setToken(null);
        setUser(null);
    };

    return (
        <AuthContext.Provider value={{ token, user, login, logout }}>
            {children}
        </AuthContext.Provider>
    );
}



------
import { useContext, useEffect, useMemo, useState } from "react";
import { AuthContext } from "../../Authentication/AuthContext";
import axios from "axios";
import SidebarWidget from "../../widgets/SidebarWidget";
import CalendarWidget from "../../widgets/CalendarWidget";
import ChatBubbleWidget from "../../widgets/ChatBubbleWidget";
import StatisticsChart from "../../components/StatisticsChart";
import OnlineCourseBanner from "../../components/OnlineCourseBanner";
import TopViewedLessonsWidget from "./TopViewedLessonsWidget";
import NotificationWidget from "../../widgets/NotificationWidget";
import ReminderBox from "../../widgets/ReminderBoxWidget";
import { Navigate } from "react-router-dom";
import JointeamWidget from "../../widgets/JointeamWidget";
import Userwidget from "../../widgets/UserAvatarWidget";

interface Lesson {
  id: string;
  title: string;
  dueDate?: string;
  assignType: string;
}

interface Reminder {
  title: string;
  dueDate: string;
}

const UserDashboard = () => {
  const { user} = useContext(AuthContext);
  const [lessons, setLessons] = useState<Lesson[]>([]);
  const [assignTypeFilter, setAssignTypeFilter] = useState<string>("all");

  useEffect(() => {
    if (!user) return;

    const fetchLessons = async () => {
      try {
        const res = await axios.get("/api/learning/upcoming-due", {
          withCredentials: true
        });
        setLessons(res.data);
      } catch (err) {
        console.error("❌ Error fetching lessons", err);
      }
    };

    fetchLessons();
  }, [user]);



  const filteredLessons = useMemo(() => {
    return lessons.filter((lesson) =>
      assignTypeFilter === "all-types" ? true : lesson.assignType === assignTypeFilter
    );
  }, [lessons, assignTypeFilter]);

  const calendarEvents = useMemo(() => {
    return filteredLessons
      .filter((lesson) => lesson.dueDate)
      .map((lesson) => ({
        title: lesson.title,
        date: lesson.dueDate!,
        id: lesson.id,
        assignType: lesson.assignType,
      }));
  }, [filteredLessons]);

  const upcomingReminders: Reminder[] = useMemo(() => {
    return calendarEvents
      .filter((e) => new Date(e.date) > new Date())
      .sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime())
      .map((e) => ({ title: e.title, dueDate: e.date }))
      .slice(0, 5);
  }, [calendarEvents]);

  if (user) return <Navigate to="/" replace />;

  // const displayName = user?.name || "User";

  return (
    <>
      <div className="min-h-screen bg-gray-50 flex">
        <SidebarWidget />

        <main className="flex-1 p-6">
          <div className="flex items-center justify-between mb-4">
            <h1 className="text-3xl font-bold text-gray-800">👋 Welcome, </h1>
            <div className="flex items-center space-x-4">
              {/* {displayName} */}
            <NotificationWidget />
            <Userwidget/>
            </div>
          
          </div>
          <div className="grid grid-cols-1 xl:grid-cols-4 gap-6">
            <div className="xl:col-span-3 space-y-6">
              <OnlineCourseBanner />
              <StatisticsChart />
              <TopViewedLessonsWidget />
              <JointeamWidget />
            </div>
            <div className="order-1 xl:order-2">
              <div className="space-y-6 mt-4 xl:mt-0">
  <div className="flex space-x-2">
    {["all", "team", "specific"].map((type) => (
      <button
        key={type}
        onClick={() => setAssignTypeFilter(type)}
        className={`px-3 py-1 rounded-md text-sm capitalize ${
          assignTypeFilter === type
            ? "bg-blue-500 text-white"
            : "bg-gray-200 hover:bg-gray-300"
        }`}
      >
        {type === "all-types" ? "All Types" : type}
      </button>
    ))}
</div>
                <CalendarWidget events={calendarEvents} />
                <ReminderBox reminders={upcomingReminders} />

              </div>
            </div>
          </div>
        </main>
      </div>
      <ChatBubbleWidget />
    </>
  );
};

export default UserDashboard;
----
import React, { useContext, useState } from "react";
import { useNavigate } from "react-router-dom";
import InstructionModal from "../../components/InstructionModal";
import axios from "axios";
import { jwtDecode } from "jwt-decode";
import { AuthContext } from "../../Authentication/AuthContext";

interface JwtPayload {
  email: string;
  role?: string;
  groups?: string[];
  [key: string]: unknown;
}

const LoginPage = () => {
  const navigate = useNavigate();
  const [showModal, setShowModal] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
    const { login } = useContext(AuthContext);
  

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    try {
      const res = await axios.post("/api/login", { email, password },{
        withCredentials:true
      });
      const token = res.data.accessToken;

      login(token)

    if (typeof token !== "string") {
      throw new Error("Invalid token format");
    }

    const role = res.data.refreshToken;

      console.log("Login Respose: ",res.data)
      if (role === "admin") {
        navigate("/admin");
      } else if (role === "supervisor") {
        navigate("/supervisor");
        
      }else{
        navigate("/dashboard");
      }
    } catch (err) {
      alert("Login failed");
      console.error("❌ Login error:", err);
    }
  };

  return (
      <div className="w-full h-screen flex flex-col md:flex-row">
        {/* Left Panel */}
        <div className="w-full md:w-1/2 h-1/2 md:h-full bg-gradient-to-b from-blue-500 to-blue-800 text-white flex flex-col justify-center items-center p-8">
          <h1 className="text-5xl font-bold mb-4 text-center">IT Learning Hub</h1>
          <p className="text-lg mb-6 text-center">E-learning-platform</p>
          <button
              onClick={() => setShowModal(true)}
              className="bg-white text-blue-700 font-semibold py-2 px-6 rounded-full shadow hover:opacity-90 transition"
          >
            Read More
          </button>
        </div>

        <div className="w-full md:w-1/2 h-1/2 md:h-full flex items-center justify-center p-8">
          <div className="w-full max-w-md">
            <h2 className="text-2xl font-bold text-gray-900 mb-1">Hello Again!</h2>
            <p className="text-sm text-gray-500 mb-6">Welcome Back</p>

            <form onSubmit={handleSubmit} className="space-y-4">
              <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="firstname.lastname@example.com"
                  className="w-full px-4 py-2 rounded-full border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  required
              />
              <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="********"
                  className="w-full px-4 py-2 rounded-full border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  required
              />
              <button
                  type="submit"
                  className="w-full bg-blue-600 text-white font-semibold py-2 rounded-full hover:bg-blue-700 transition"
              >
                Login
              </button>
            </form>

            <div className="text-center mt-4">
              <a href="/register" className="text-sm text-blue-600 hover:underline">
                Don't have an account? Register
              </a>
            </div>
          </div>
        </div>

        <InstructionModal isOpen={showModal} onClose={() => setShowModal(false)} />
      </div>
  );
};

export default LoginPage;
----
package Testing;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import model.User;
import util.JwtUtil;
import org.mindrot.jbcrypt.BCrypt;

import java.time.Duration;
import java.util.Map;

@Path("/login")
//@RunOnVirtualThread
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class LoginResource {

    @Inject
    EntityManager em;

    @POST
    @Transactional

    public Response login(LoginRequest request) {
        System.out.println("🔐 Attempt login: " + request.email);

        try {
            User user = em.createQuery(
                            "SELECT u FROM User u WHERE u.email = :email", User.class)
                    .setParameter("email", request.email)
                    .getSingleResult();

            if (!BCrypt.checkpw(request.password, user.getPassword())) {
                System.out.println("❌ Invalid password for: " + request.email);
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity(new ErrorResponse("Invalid credentials"))
                        .build();
            }

            String accessToken = JwtUtil.generateToken(user.getEmail(), user.getRole(), user.getName());
            String refreshToken = JwtUtil.generateRefreshToken(user.getEmail(), user.getRole(), user.getName());

            System.out.println("accessToken: " + accessToken);
            System.out.println("refreshToken: " + refreshToken);


            NewCookie accessCookie = new NewCookie(
                    "access_token", accessToken, "/", null, null, 7200, true, true);


            NewCookie refreshCookie = new NewCookie(
                    "refresh_token", refreshToken, "/", null, null, 604800, true, true); // 7 days



            System.out.println("✅ Login success: " + request.email);
            
            return Response.ok(new LoginResponse(accessToken, user.getRole()))
                    .cookie(accessCookie)
                    .cookie(refreshCookie)
                    .build();



        } catch (NoResultException e) {
            System.out.println("❌ User not found: " + request.email);
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(new ErrorResponse("User not found"))
                    .build();
        }
    }

    public static class LoginRequest {
        public String email;
        public String password;
    }

    public static class LoginResponse {
        public String accessToken;
        public String refreshToken;

        public LoginResponse(String accessToken, String refreshToken) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
        }
    }

    public static class ErrorResponse {
        public String error;

        public ErrorResponse(String error) {
            this.error = error;
        }
    }
}
