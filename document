import { useContext, useEffect, useRef, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import axios from "axios";
import { AuthContext } from "../../Authentication/AuthContext";
import Sidebar from "../../widgets/SidebarWidget";
import defaultUserAvatar from "../../assets/user.png";
import ChatBubbleWidget from "../../widgets/ChatBubbleWidget";
import NotificationWidget from "../../widgets/NotificationWidget";

interface Lesson {
  id: string;
  title: string;
  category: string;
  description?: string;
  thumbnailUrl?: string;
  authorName?: string;
  authorAvatarUrl?: string;
  assignType: string;
  assignedUserIds?: string[];
  assignedTeamIds?: string[];
  contentType: "video" | "document";
}

interface Progress {
  percent: number;
  lastTimestamp: number;
}

const LessonPage = () => {
  const { token: ctxToken } = useContext(AuthContext);
  const token = ctxToken || localStorage.getItem("token") || sessionStorage.getItem("token");

  const navigate = useNavigate();
  const location = useLocation();
  const menuRef = useRef<HTMLDivElement>(null);

  const [lessons, setLessons] = useState<Lesson[]>([]);
  const [progressMap, setProgressMap] = useState<Record<string, Progress>>({});
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [categoryMenuOpen, setCategoryMenuOpen] = useState(false);
  const [selectedCategories, setSelectedCategories] = useState<string[]>([]);
  const [selectedAssignType, setSelectedAssignType] = useState<string>("all");
  const [userId, setUserId] = useState<string | null>(null);
  const [myTeamIds, setMyTeamIds] = useState<string[]>([]);

  useEffect(() => {
    const fetchTeams = async () => {
      try {
        const res = await axios.get("/api/teams", {
          headers: { Authorization: `Bearer ${token}` },
        });
        setMyTeamIds(res.data.map((team: { id: string }) => team.id));
      } catch (error) {
        console.error("❌ Failed to fetch user teams:", error);
      }
    };
    if (token) fetchTeams();
  }, [token]);

  useEffect(() => {
    const fetchUserProfile = async () => {
      try {
        const res = await axios.get("/api/profile", {
          headers: { Authorization: `Bearer ${token}` },
        });
        setUserId(res.data.id);
        setMyTeamIds(res.data.teams || []);
      } catch (error) {
        console.error("❌ Failed to fetch user profile:", error);
      }
    };
    if (token) fetchUserProfile();
  }, [token]);

  useEffect(() => {
    if (!token) {
      navigate("/");
      return;
    }

    const fetchData = async () => {
      try {
        const [lessonsRes, progressRes] = await Promise.all([
          axios.get("/api/learning", {
            headers: { Authorization: `Bearer ${token}` },
          }),
          axios.get("/api/user/progress", {
            headers: { Authorization: `Bearer ${token}` },
          }),
        ]);
        setLessons(lessonsRes.data);
        
        const map: Record<string, Progress> = {};
        progressRes.data.forEach((item: { lessonId: string; percent: number; lastTimestamp?: number }) => {
          const key = item.lessonId.toLowerCase();
          map[key] = {
            percent: item.percent,
            lastTimestamp: item.lastTimestamp || 0,
          };
        });
        setProgressMap(map);
      } catch (err) {
        console.error("❌ Failed to fetch lessons or progress:", err);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [token, location.pathname, navigate]);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setCategoryMenuOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const categories = Array.from(new Set(lessons.map((l) => l.category).filter(Boolean)));

 

 const filteredLessons = lessons.filter((lesson) => {
  const key = lesson.id.toLowerCase();
  const progress = progressMap[key]?.percent ?? 0;

  const isIncomplete = progress < 100;

  const matchesAssignType =
    selectedAssignType === "all"
      ? lesson.assignType === "all"
      : selectedAssignType === "specific"
      ? lesson.assignType === "specific" && userId && lesson.assignedUserIds?.includes(userId)
      : selectedAssignType === "team"
      ? lesson.assignType === "team" && lesson.assignedTeamIds?.some((id) => myTeamIds.includes(id))
      : false;

  const matchesSearch = [lesson.title, lesson.category, lesson.description ?? ""].some((v) =>
    v.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const matchesCategory =
    selectedCategories.length === 0 || selectedCategories.includes(lesson.category);

  return isIncomplete && matchesAssignType && matchesSearch && matchesCategory;
});

  const handleLessonClick = async (id: string) => {
    const key = id.toLowerCase();
    const lastTimestamp = progressMap[key]?.lastTimestamp || 0;

    try {
      await axios.post(`/api/learning/${id}/click`, {}, {
        headers: { Authorization: `Bearer ${token}` },
      });
    } catch (err) {
      console.error("Failed to log click:", err);
    } finally {
      navigate(`/lesson/${id}`, { state: { lastTimestamp } });
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex">
      <Sidebar />
      <main className="flex-1 p-6">
        <div className="flex items-center justify-between mb-4">
          <input
            type="text"
            placeholder="Search lessons…"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full xl:w-1/3 p-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-purple-500"
          />
          <div className="flex items-center space-x-4">
            {/* Category Filter */}
            <div className="relative" ref={menuRef}>
              <button
                onClick={() => setCategoryMenuOpen(!categoryMenuOpen)}
                className="px-3 py-2 border border-gray-300 rounded-md shadow-sm bg-white hover:bg-gray-100 text-sm"
              >
                {selectedCategories.length > 0
                  ? `Category (${selectedCategories.length})`
                  : "Filter by Category"}
              </button>

              {categoryMenuOpen && (
                <div className="absolute z-10 mt-2 w-48 bg-white border border-gray-200 rounded-md shadow-lg">
                  <div className="p-2 space-y-1">
                    {categories.map((category) => (
                      <label key={category} className="flex items-center space-x-2 text-sm cursor-pointer">
                        <input
                          type="checkbox"
                          checked={selectedCategories.includes(category)}
                          onChange={() =>
                            setSelectedCategories((prev) =>
                              prev.includes(category)
                                ? prev.filter((c) => c !== category)
                                : [...prev, category]
                            )
                          }
                          className="accent-purple-500"
                        />
                        <span>{category}</span>
                      </label>
                    ))}
                    <button
                      className="mt-2 text-xs text-blue-500 hover:underline"
                      onClick={() => setSelectedCategories([])}
                    >
                      Clear All
                    </button>
                  </div>
                </div>
              )}
            </div>

            {/* Assign Type Filter */}
            <div className="flex space-x-2">
              {["all", "team", "specific"].map((type) => (
                <button
                  key={type}
                  onClick={() => setSelectedAssignType(type)}
                  className={`px-3 py-1 rounded-md text-sm ${
                    selectedAssignType === type
                      ? "bg-purple-500 text-white"
                      : "bg-gray-200 hover:bg-gray-300"
                  }`}
                >
                  {type.charAt(0).toUpperCase() + type.slice(1)}
                </button>
              ))}
            </div>

            <NotificationWidget />
          </div>
        </div>
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          <div className="xl:col-span-3 grid gap-6 grid-cols-[repeat(auto-fill,minmax(256px,1fr))]">
            {loading ? (
              <div className="text-gray-500">Loading lessons…</div>
            ) : filteredLessons.length === 0 ? (
              <div className="text-gray-500">No lessons found</div>
            ) : (
              filteredLessons.map((lesson) => {
                const key = lesson.id.toLowerCase();
                const progress = progressMap[key] ?? { percent: 0, lastTimestamp: 0 };

                const avatarFilename = lesson.authorAvatarUrl?.split("/").pop();
                const avatarUrl = avatarFilename && avatarFilename !== "null"
                  ? `/api/profile/avatars/${avatarFilename}`
                  : defaultUserAvatar;
                return (
                  <button
                    key={lesson.id}
                    onClick={() => handleLessonClick(lesson.id)}
                    className="block focus:outline-none focus-visible:ring-2 focus-visible:ring-purple-500"
                  >
                    <div className="w-64 h-[300px] bg-white rounded-xl shadow-md flex flex-col overflow-hidden">
                      <div className="w-full h-32 bg-gray-100">
                        <img
                          src={lesson.thumbnailUrl || "/placeholder.png"}
                          alt={lesson.title}
                          onError={(e) => {
                            e.currentTarget.onerror = null;
                            e.currentTarget.src = "/placeholder.png";
                          }}
                          className="h-full w-full object-cover"
                        />
                      </div>

                      <div className="flex flex-1 flex-col p-4">
                        <span className="text-[10px] font-semibold uppercase text-purple-600">
                          {lesson.category}
                        </span>
                        <h3 className="mt-1 line-clamp-2 text-sm font-semibold">{lesson.title}</h3>

                        <div className="mb-2 mt-3 h-1 rounded-full bg-gray-200">
                          <div
                            className="h-full transition-all duration-300 rounded-full bg-blue-500"
                            style={{
                              width: `${Math.max(progress.percent, 1)}%`,
                              minWidth: progress.percent > 0 ? 4 : 0,
                            }}
                          />
                        </div>
                        <div className="text-[10px] text-gray-500 mb-1">
                          Progress: {progress.percent}%
                        </div>

                        <div className="mt-auto flex items-center space-x-2">
                          <img
                            src={avatarUrl}
                            alt="Author"
                            onError={(e) => {
                              e.currentTarget.onerror = null;
                              e.currentTarget.src = defaultUserAvatar;
                            }}
                            className="h-7 w-7 rounded-full object-cover"
                          />
                          <div>
                            <div className="text-xs font-medium">
                              {lesson.authorName || "Unknown Author"}
                            </div>
                            <div className="text-[10px] text-gray-500">Learning Content</div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </div>
      </main>
      <ChatBubbleWidget />
    </div>
  );
};

export default LessonPage;
