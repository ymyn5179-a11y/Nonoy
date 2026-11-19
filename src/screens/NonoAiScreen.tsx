import React, { useEffect, useRef, useState } from 'react';
import {
  ArrowRight,
  Bot,
  HelpCircle,
  Lightbulb,
  Lock,
  Mic,
  MicOff,
  Pause,
  Play,
  Send,
  ShieldCheck,
  Sparkles,
  Square,
  Volume2,
  VolumeX,
} from 'lucide-react';
import { NonoCharacter } from '../components/NonoCharacter';
import { NonoLandLogo } from '../components/NonoLandLogo';
import { useNonoLand } from '../context/NonoLandContext';
import { AppScreen, NonoAiChatResponse, NonoMood } from '../types/nonoland';
import { trackedFetch } from '../utils/perfMonitor';
import { soundEngine } from '../utils/soundEngine';

interface ChatTurn {
  id: string;
  sender: 'child' | 'nono';
  text: string;
  hint?: string;
  explanation?: string;
  followUpQuestion?: string;
  recommendedScreen?: AppScreen;
  mood?: NonoMood;
  blocked?: boolean;
}

const VOICE_OPTIONS = [
  { id: 'Zephyr', ar: 'نسيم (دافئ ومرح)', en: 'Zephyr (Warm & Playful)' },
  { id: 'Kore', ar: 'كوري (هادئ ولطيف)', en: 'Kore (Calm & Gentle)' },
  { id: 'Puck', ar: 'باك (نشيط)', en: 'Puck (Cheerful)' },
  { id: 'Charon', ar: 'شارون (قصصي)', en: 'Charon (Storyteller)' },
  { id: 'Fenrir', ar: 'فنرير (واضح)', en: 'Fenrir (Clear)' },
] as const;

const QUICK_PROMPTS = [
  {
    id: 'letters',
    ar: 'اشرح لي الفرق بين الباء والتاء بأسلوب ممتع!',
    en: 'Explain the letter B and its sound in a fun way!',
    topic: 'Letters & Phonics',
    mode: 'explain' as const,
  },
  {
    id: 'math-hint',
    ar: 'أعطني تلميحاً لطيفاً لسؤال: كم يساوي ٣ + ٢؟',
    en: 'Give me a gentle hint for: What is 3 + 2?',
    topic: 'Counting & Math',
    mode: 'hint' as const,
  },
  {
    id: 'science',
    ar: 'لماذا نرى قوس قزح بعد المطر؟',
    en: 'Why do we see a rainbow after rain?',
    topic: 'Science Discovery',
    mode: 'explain' as const,
  },
  {
    id: 'encourage',
    ar: 'أشعر ببعض الصعوبة، شجّعني يا نونو!',
    en: 'This feels tricky, cheer me on Nono!',
    topic: 'Confidence',
    mode: 'encourage' as const,
  },
];

interface BrowserSpeechRecognition {
  lang: string;
  interimResults: boolean;
  maxAlternatives: number;
  onresult: ((evt: { results: ArrayLike<ArrayLike<{ transcript: string }>> }) => void) | null;
  onerror: (() => void) | null;
  onend: (() => void) | null;
  start: () => void;
  stop: () => void;
}

export const NonoAiScreen: React.FC = () => {
  const { activeChild, authSession, isChildSession, language, navigate, parentSettings } = useNonoLand();
  const [aiStatus, setAiStatus] = useState<{
    configured: boolean;
    voiceSynthesisSupported: boolean;
    dailyLimitPerChild: number;
  } | null>(null);
  const [voiceAllowedByFamily, setVoiceAllowedByFamily] = useState<boolean>(true);
  const [aiAllowedByFamily, setAiAllowedByFamily] = useState<boolean>(true);
  const [mode, setMode] = useState<'explain' | 'hint' | 'question' | 'encourage'>('explain');
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const [usageRemaining, setUsageRemaining] = useState<number | null>(null);
  const [nonoMood, setNonoMood] = useState<NonoMood>('waving');

  // Voice Companion controls
  const [voiceMuted, setVoiceMuted] = useState<boolean>(parentSettings.muted);
  const [selectedVoice, setSelectedVoice] = useState<string>('Zephyr');
  const [speakingTurnId, setSpeakingTurnId] = useState<string | null>(null);
  const [speechPaused, setSpeechPaused] = useState(false);
  const [micListening, setMicListening] = useState(false);
  const [micNotice, setMicNotice] = useState<string | null>(null);

  const audioRef = useRef<HTMLAudioElement | null>(null);
  const recognitionRef = useRef<BrowserSpeechRecognition | null>(null);

  const [turns, setTurns] = useState<ChatTurn[]>([
    {
      id: 'welcome',
      sender: 'nono',
      text:
        language === 'ar'
          ? `مرحباً ${activeChild?.displayName || ''}! أنا نونو صديقك الذكي. اسألني عن الحروف، الأرقام، أو العلوم وسأساعدك بتلميحات لطيفة خطوة بخطوة!`
          : `Hi ${activeChild?.displayName || ''}! I am Nono, your smart learning buddy. Ask me about letters, numbers, or science for gentle step-by-step hints!`,
      mood: 'waving',
    },
  ]);

  useEffect(() => {
    trackedFetch('/api/ai/status')
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d) {
          setAiStatus({
            configured: Boolean(d.configured),
            voiceSynthesisSupported: Boolean(d.voiceSynthesisSupported),
            dailyLimitPerChild: d.dailyLimitPerChild || 40,
          });
        }
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!authSession.authenticated || !activeChild || activeChild.id.startsWith('demo-')) return;
    fetch(`/api/family/children/${encodeURIComponent(activeChild.id)}/ai-usage`, {
      credentials: 'include',
    })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d) {
          setAiAllowedByFamily(d.aiAssistantEnabled !== false);
          setVoiceAllowedByFamily(d.voiceEnabled !== false);
          if (typeof d.dailyLimit === 'number' && typeof d.usedToday === 'number') {
            setUsageRemaining(Math.max(0, d.dailyLimit - d.usedToday));
          }
        }
      })
      .catch(() => {});
  }, [authSession.authenticated, activeChild]);

  useEffect(() => {
    return () => {
      if (audioRef.current) {
        audioRef.current.pause();
        audioRef.current = null;
      }
      soundEngine.stopSpeech();
      if (recognitionRef.current) {
        try {
          recognitionRef.current.stop();
        } catch {
          // ignore
        }
      }
    };
  }, []);

  if (!activeChild) return null;

  const isEnabledForChild = activeChild.aiAssistantEnabled !== false && aiAllowedByFamily;
  const isVoiceEnabled = !voiceMuted && !parentSettings.muted && parentSettings.voiceNarration && voiceAllowedByFamily;

  const stopVoicePlayback = () => {
    if (audioRef.current) {
      audioRef.current.pause();
      audioRef.current.currentTime = 0;
      audioRef.current = null;
    }
    soundEngine.stopSpeech();
    setSpeakingTurnId(null);
    setSpeechPaused(false);
  };

  const togglePausePlayback = () => {
    if (audioRef.current) {
      if (audioRef.current.paused) {
        void audioRef.current.play();
        setSpeechPaused(false);
      } else {
        audioRef.current.pause();
        setSpeechPaused(true);
      }
      return;
    }
    if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
      if (speechPaused) {
        window.speechSynthesis.resume();
        setSpeechPaused(false);
      } else {
        window.speechSynthesis.pause();
        setSpeechPaused(true);
      }
    }
  };

  const speakTurn = async (turnId: string, text: string) => {
    if (!text.trim() || !isVoiceEnabled) return;
    stopVoicePlayback();
    setSpeakingTurnId(turnId);
    setSpeechPaused(false);

    // 1. Try server Gemini TTS first when authenticated & configured
    if (authSession.authenticated && aiStatus?.voiceSynthesisSupported) {
      try {
        const res = await trackedFetch('/api/ai/tts', {
          method: 'POST',
          credentials: 'include',
          headers: {
            'Content-Type': 'application/json',
            ...(authSession.csrfToken ? { 'x-csrf-token': authSession.csrfToken } : {}),
          },
          body: JSON.stringify({
            childId: activeChild.id,
            text: text.slice(0, 300),
            voiceName: selectedVoice,
            language,
          }),
        });
        if (res.ok) {
          const data = (await res.json()) as { audioBase64?: string; mimeType?: string };
          if (data.audioBase64) {
            const audio = new Audio(`data:${data.mimeType || 'audio/wav'};base64,${data.audioBase64}`);
            audioRef.current = audio;
            audio.onended = () => {
              setSpeakingTurnId(null);
              setSpeechPaused(false);
            };
            audio.onerror = () => {
              setSpeakingTurnId(null);
              soundEngine.speak(text, language);
            };
            await audio.play();
            return;
          }
        } else if (res.status === 403) {
          setVoiceAllowedByFamily(false);
          setSpeakingTurnId(null);
          return;
        }
      } catch {
        // fallback cleanly to local Web Speech synthesis
      }
    }

    // 2. Fallback cleanly to Web Speech synthesis
    if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
      try {
        window.speechSynthesis.cancel();
        const utter = new SpeechSynthesisUtterance(text);
        utter.lang = language === 'ar' ? 'ar-SA' : 'en-US';
        utter.rate = 0.92;
        utter.pitch = 1.08;
        utter.onend = () => {
          setSpeakingTurnId(null);
          setSpeechPaused(false);
        };
        utter.onerror = () => {
          setSpeakingTurnId(null);
          setSpeechPaused(false);
        };
        window.speechSynthesis.speak(utter);
        return;
      } catch {
        // ignore
      }
    }
    setSpeakingTurnId(null);
  };

  const toggleVoiceInput = () => {
    setMicNotice(null);
    if (!voiceAllowedByFamily || !isEnabledForChild) {
      setMicNotice(
        language === 'ar'
          ? 'التفاعل الصوتي غير متاح حالياً حسب إعدادات الوالدين أو موافقة الخصوصية.'
          : 'Voice interaction is currently disabled by Parent Controls or Privacy Consent.',
      );
      return;
    }

    if (micListening && recognitionRef.current) {
      recognitionRef.current.stop();
      setMicListening(false);
      return;
    }

    const SpeechRecCtor =
      typeof window !== 'undefined'
        ? ((window as unknown as { SpeechRecognition?: new () => BrowserSpeechRecognition; webkitSpeechRecognition?: new () => BrowserSpeechRecognition }).SpeechRecognition ||
           (window as unknown as { webkitSpeechRecognition?: new () => BrowserSpeechRecognition }).webkitSpeechRecognition)
        : undefined;

    if (!SpeechRecCtor) {
      setMicNotice(
        language === 'ar'
          ? 'التعرف الصوتي المباشر غير مدعوم في هذا المتصفح — يمكنك كتابة سؤالك أو استخدام الأسئلة السريعة.'
          : 'Live Speech Recognition is not supported in this browser — please type or tap a quick question.',
      );
      return;
    }

    try {
      const rec = new SpeechRecCtor();
      rec.lang = language === 'ar' ? 'ar-SA' : 'en-US';
      rec.interimResults = false;
      rec.maxAlternatives = 1;
      rec.onresult = (evt) => {
        const transcript = evt.results?.[0]?.[0]?.transcript || '';
        if (transcript.trim()) {
          setInput((prev) => (prev ? `${prev} ${transcript}` : transcript));
        }
      };
      rec.onerror = () => {
        setMicListening(false);
        setMicNotice(
          language === 'ar'
            ? 'لم نتمكن من سماع الصوت — تأكد من إذن الميكروفون أو اكتب سؤالك.'
            : 'Could not capture audio — check browser microphone permission or type below.',
        );
      };
      rec.onend = () => {
        setMicListening(false);
      };
      recognitionRef.current = rec;
      setMicListening(true);
      rec.start();
    } catch {
      setMicListening(false);
      setMicNotice(
        language === 'ar'
          ? 'تعذر بدء الميكروفون. استخدم الكتابة أو البطاقات الجاهزة.'
          : 'Unable to start microphone. Please type or use quick prompts.',
      );
    }
  };

  const sendPrompt = async (
    textToSend: string,
    overrideMode?: 'explain' | 'hint' | 'question' | 'encourage',
    topic?: string,
  ) => {
    const clean = textToSend.trim();
    if (!clean || loading) return;

    if (!authSession.authenticated) {
      setErrorBanner(
        language === 'ar'
          ? 'يرجى تسجيل دخول ولي الأمر أو الطفل لاستخدام مساعد نونو الذكي الآمن.'
          : 'Please sign in with your parent or child account to chat with Nono AI safely.',
      );
      return;
    }

    if (!isEnabledForChild) {
      setErrorBanner(
        language === 'ar'
          ? 'مساعد نونو الذكي متوقف حالياً من إعدادات الوالدين أو موافقات الخصوصية.'
          : 'Nono AI Assistant is currently turned off in Parent Controls or Privacy Consent.',
      );
      return;
    }

    setErrorBanner(null);
    setTurns((prev) => [...prev, { id: `c-${Date.now()}`, sender: 'child', text: clean }]);
    setInput('');
    setLoading(true);
    setNonoMood('thinking');

    try {
      const res = await trackedFetch('/api/ai/nono-chat', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          ...(authSession.csrfToken ? { 'x-csrf-token': authSession.csrfToken } : {}),
        },
        body: JSON.stringify({
          childId: activeChild.id,
          message: clean,
          mode: overrideMode || mode,
          language,
          currentTopic: topic,
          attemptCount: turns.filter((t) => t.sender === 'child').length,
        }),
      });

      const data = (await res.json()) as Partial<NonoAiChatResponse> & { error?: string; code?: string };

      if (!res.ok) {
        setNonoMood('encouraging');
        if (res.status === 403) {
          setAiAllowedByFamily(false);
        }
        setErrorBanner(
          data.code === 'AI_KEY_MISSING'
            ? language === 'ar'
              ? 'مفتاح GEMINI_API_KEY غير مفعّل على الخادم حالياً. أضفه في إعدادات البيئة لتفعيل الردود الذكية الحقيقية.'
              : 'GEMINI_API_KEY is not configured on the server yet. Add it in environment Secrets to enable live Nono AI tutoring.'
            : data.error || (language === 'ar' ? 'تعذّر الاتصال بمساعد نونو الآن.' : 'Could not reach Nono AI right now.'),
        );
        return;
      }

      const nextMood = data.mood || 'encouraging';
      setNonoMood(nextMood);
      if (typeof data.usageRemaining === 'number') setUsageRemaining(data.usageRemaining);

      const replyText = data.reply || '';
      const turnId = `n-${Date.now()}`;
      setTurns((prev) => [
        ...prev,
        {
          id: turnId,
          sender: 'nono',
          text: replyText,
          hint: data.hint,
          explanation: data.explanation,
          followUpQuestion: data.followUpQuestion,
          recommendedScreen: data.recommendedScreen,
          mood: nextMood,
          blocked: data.blocked,
        },
      ]);

      soundEngine.playSuccess();
      if (replyText && isVoiceEnabled) {
        void speakTurn(turnId, replyText);
      }
    } catch {
      setErrorBanner(
        language === 'ar' ? 'حدث خطأ في الاتصال بالخادم.' : 'Network error connecting to Nono AI.',
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-5">
      {/* Header Banner */}
      <div className="nono-card rounded-[2rem] p-5 sm:p-6 bg-gradient-to-r from-[#F3ECFF] via-[#EBF5FF] to-[#FFF8E9] flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div
            className={`relative rounded-full p-1 transition-all ${
              speakingTurnId ? 'ring-4 ring-[#8054D9] bg-[#8054D9]/10 animate-pulse' : ''
            }`}
          >
            <NonoCharacter
              mood={speakingTurnId ? 'excited' : nonoMood}
              scarfColor={activeChild.companionScarfColor}
              size="md"
              language={language}
            />
          </div>
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <NonoLandLogo variant="badge" size="xs" language={language} />
              <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-white text-xs font-extrabold text-[#8054D9] border border-[#8054D9]/20">
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>{language === 'ar' ? 'رفيق نونو الصوتي والتعليمي الآمن' : 'Nono Voice & AI Companion'}</span>
              </div>
              {speakingTurnId && (
                <span className="px-2.5 py-0.5 rounded-full bg-[#DCFCE7] text-[#15803D] text-[11px] font-extrabold">
                  {language === 'ar' ? '🔊 نونو يتحدث الآن...' : '🔊 Nono is speaking...'}
                </span>
              )}
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-[#27345C] flex items-center gap-2">
              <Bot className="w-7 h-7 text-[#8054D9]" />
              <span>{language === 'ar' ? 'مساعد نونو الصوتي الذكي' : 'Nono AI Voice Companion'}</span>
            </h1>
            <p className="text-xs sm:text-sm font-bold text-[#27345C]/75">
              {language === 'ar'
                ? `مخصّص لـ ${activeChild.displayName} (المستكشفون الصغار · ١–٤ سنوات) · تلميحات متدرجة وصوت لطيف`
                : `Tailored for ${activeChild.displayName} (Little Explorers · 1–4 Years) · Gentle hints & spoken guidance`}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs font-extrabold">
          {usageRemaining !== null && (
            <span className="px-3 py-1.5 rounded-xl bg-white border border-[#27345C]/12 text-[#27345C]">
              {language === 'ar' ? `المتبقي اليوم: ${usageRemaining}` : `Left today: ${usageRemaining}`}
            </span>
          )}
          {aiStatus && !aiStatus.configured && (
            <span className="px-3 py-1.5 rounded-xl bg-[#FEF3C7] text-[#92400E] border border-[#F59E0B]/40">
              {language === 'ar' ? 'بانتظار GEMINI_API_KEY' : 'GEMINI_API_KEY needed'}
            </span>
          )}
        </div>
      </div>

      {/* Voice Companion Controls Strip */}
      <div className="nono-card p-4 bg-white flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => {
              const next = !voiceMuted;
              setVoiceMuted(next);
              if (next) stopVoicePlayback();
            }}
            className={`min-h-[42px] px-3.5 rounded-xl border-2 text-xs font-extrabold flex items-center gap-1.5 cursor-pointer ${
              voiceMuted || !voiceAllowedByFamily
                ? 'bg-[#FEF2F2] border-[#FECACA] text-[#991B1B]'
                : 'bg-[#E2F9EC] border-[#55D98B] text-[#14532D]'
            }`}
          >
            {voiceMuted || !voiceAllowedByFamily ? <VolumeX className="w-4 h-4" /> : <Volume2 className="w-4 h-4" />}
            <span>
              {!voiceAllowedByFamily
                ? language === 'ar' ? 'الصوت متوقف من الوالدين' : 'Voice Paused by Parent'
                : voiceMuted
                  ? language === 'ar' ? 'الصوت مكتوم' : 'Voice Muted'
                  : language === 'ar' ? 'الصوت مفعّل' : 'Voice Active'}
            </span>
          </button>

          {speakingTurnId && (
            <>
              <button
                type="button"
                onClick={togglePausePlayback}
                className="min-h-[42px] px-3 rounded-xl bg-[#FFF8E9] border border-[#27345C]/15 text-xs font-extrabold flex items-center gap-1 cursor-pointer"
              >
                {speechPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
                <span>{speechPaused ? (language === 'ar' ? 'متابعة' : 'Resume') : (language === 'ar' ? 'إيقاف مؤقت' : 'Pause')}</span>
              </button>
              <button
                type="button"
                onClick={stopVoicePlayback}
                className="min-h-[42px] px-3 rounded-xl bg-[#FEE2E2] text-[#991B1B] text-xs font-extrabold flex items-center gap-1 cursor-pointer"
              >
                <Square className="w-3.5 h-3.5" />
                <span>{language === 'ar' ? 'إيقاف الصوت' : 'Stop Voice'}</span>
              </button>
            </>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <label className="text-xs font-extrabold text-[#27345C]/70">
            {language === 'ar' ? 'نبرة نونو:' : 'Nono Voice:'}
          </label>
          <select
            value={selectedVoice}
            onChange={(e) => setSelectedVoice(e.target.value)}
            disabled={!voiceAllowedByFamily}
            className="min-h-[40px] px-3 rounded-xl bg-[#FFF8E9] border border-[#27345C]/15 text-xs font-extrabold text-[#27345C]"
          >
            {VOICE_OPTIONS.map((v) => (
              <option key={v.id} value={v.id}>
                {v[language]}
              </option>
            ))}
          </select>
        </div>
      </div>

      {!isEnabledForChild && (
        <div className="nono-card p-5 bg-[#FFFBEB] border-2 border-[#FFD84D] flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <Lock className="w-6 h-6 text-[#B45309] shrink-0" />
            <div>
              <p className="font-extrabold text-[#27345C]">
                {language === 'ar'
                  ? 'تم إيقاف مساعد نونو الذكي من لوحة الوالدين أو مركز الخصوصية'
                  : 'Nono AI Assistant is paused by Parent Settings or Privacy Consent'}
              </p>
              <p className="text-xs font-bold text-[#27345C]/75">
                {language === 'ar'
                  ? 'يمكن لولي الأمر إعادة تفعيله في أي وقت من لوحة تحكم العائلة.'
                  : 'A parent can re-enable it anytime in the Family Dashboard.'}
              </p>
            </div>
          </div>
          {!isChildSession && (
            <button
              type="button"
              onClick={() => navigate('parent-dashboard')}
              className="min-h-[42px] px-4 rounded-xl bg-[#27345C] text-white text-xs font-extrabold cursor-pointer"
            >
              {language === 'ar' ? 'لوحة الوالدين' : 'Parent Dashboard'}
            </button>
          )}
        </div>
      )}

      {/* Mode Selector + Quick Prompts */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <div className="lg:col-span-4 space-y-4">
          <div className="nono-card p-4 bg-white space-y-2.5">
            <p className="text-xs font-extrabold text-[#27345C]/70">
              {language === 'ar' ? 'كيف تحب أن يساعدك نونو؟' : 'How should Nono help?'}
            </p>
            <div className="grid grid-cols-2 gap-2">
              {[
                { id: 'explain' as const, ar: 'اشرح لي', en: 'Explain', icon: '📘' },
                { id: 'hint' as const, ar: 'أعطني تلميحاً', en: 'Give Hint', icon: '💡' },
                { id: 'question' as const, ar: 'اسألني سؤالاً', en: 'Quiz Me', icon: '❓' },
                { id: 'encourage' as const, ar: 'شجّعني', en: 'Encourage', icon: '🌟' },
              ].map((m) => (
                <button
                  key={m.id}
                  type="button"
                  onClick={() => {
                    soundEngine.playPop();
                    setMode(m.id);
                  }}
                  className={`min-h-[44px] px-3 rounded-xl text-xs font-extrabold border-2 flex items-center gap-1.5 cursor-pointer transition-colors ${
                    mode === m.id
                      ? 'bg-[#8054D9] text-white border-[#8054D9]'
                      : 'bg-[#FFF8E9]/60 text-[#27345C] border-[#27345C]/10'
                  }`}
                >
                  <span>{m.icon}</span>
                  <span>{m[language]}</span>
                </button>
              ))}
            </div>
          </div>

          <div className="nono-card p-4 bg-white space-y-2.5">
            <p className="text-xs font-extrabold text-[#27345C]/70 flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-[#8054D9]" />
              <span>{language === 'ar' ? 'أسئلة سريعة آمنة' : 'Safe Quick Questions'}</span>
            </p>
            <div className="space-y-2">
              {QUICK_PROMPTS.map((qp) => (
                <button
                  key={qp.id}
                  type="button"
                  disabled={!isEnabledForChild || loading}
                  onClick={() => void sendPrompt(qp[language], qp.mode, qp.topic)}
                  className="w-full p-3 rounded-2xl bg-[#F8FAFC] hover:bg-[#F3ECFF] border border-[#27345C]/10 text-start text-xs font-bold text-[#27345C] cursor-pointer transition-colors disabled:opacity-50"
                >
                  {qp[language]}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Conversation Panel */}
        <div className="lg:col-span-8 nono-card p-5 bg-white flex flex-col justify-between min-h-[460px] space-y-4">
          <div className="space-y-3 max-h-[380px] overflow-y-auto pe-1">
            {turns.map((turn) => (
              <div
                key={turn.id}
                className={`flex ${turn.sender === 'child' ? 'justify-end' : 'justify-start'}`}
              >
                <div
                  className={`max-w-[88%] rounded-2xl p-4 space-y-2 ${
                    turn.sender === 'child'
                      ? 'bg-[#8054D9] text-white'
                      : turn.blocked
                        ? 'bg-[#FFFBEB] border-2 border-[#FFD84D] text-[#27345C]'
                        : 'bg-[#F8FAFC] border border-[#27345C]/10 text-[#27345C]'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <p className="text-sm font-bold leading-relaxed">{turn.text}</p>
                    {turn.sender === 'nono' && (
                      <button
                        type="button"
                        disabled={!isVoiceEnabled}
                        onClick={() => void speakTurn(turn.id, turn.text)}
                        className={`p-2 rounded-xl border shrink-0 cursor-pointer disabled:opacity-40 ${
                          speakingTurnId === turn.id
                            ? 'bg-[#8054D9] text-white border-[#8054D9]'
                            : 'bg-white text-[#8054D9] border-[#27345C]/10'
                        }`}
                        title={language === 'ar' ? 'استمع لصوت نونو' : 'Listen to Nono'}
                      >
                        <Volume2 className="w-4 h-4" />
                      </button>
                    )}
                  </div>

                  {turn.hint && (
                    <div className="p-2.5 rounded-xl bg-white border border-[#8054D9]/20 text-xs font-bold flex items-start gap-1.5">
                      <Lightbulb className="w-3.5 h-3.5 text-[#D97706] shrink-0 mt-0.5" />
                      <span>{turn.hint}</span>
                    </div>
                  )}

                  {turn.explanation && (
                    <p className="text-xs font-bold text-[#27345C]/75">{turn.explanation}</p>
                  )}

                  {turn.followUpQuestion && (
                    <div className="p-2.5 rounded-xl bg-[#E5F6FF] text-xs font-extrabold text-[#1E3A8A] flex items-center gap-1.5">
                      <HelpCircle className="w-3.5 h-3.5 shrink-0" />
                      <span>{turn.followUpQuestion}</span>
                    </div>
                  )}

                  {turn.recommendedScreen && (
                    <button
                      type="button"
                      onClick={() => navigate(turn.recommendedScreen!)}
                      className="min-h-[34px] px-3 rounded-xl bg-[#55D98B] text-[#27345C] text-xs font-extrabold inline-flex items-center gap-1 cursor-pointer"
                    >
                      <span>{language === 'ar' ? 'انتقل للتدريب' : 'Open Activity'}</span>
                      <ArrowRight className="w-3 h-3" />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>

          {errorBanner && (
            <div className="p-3 rounded-2xl bg-[#FEF2F2] border border-[#FECACA] text-xs font-extrabold text-[#991B1B]">
              {errorBanner}
            </div>
          )}

          {micNotice && (
            <div className="p-3 rounded-2xl bg-[#FFF8E9] border border-[#FFD84D] text-xs font-bold text-[#92400E]">
              {micNotice}
            </div>
          )}

          <form
            onSubmit={(e) => {
              e.preventDefault();
              void sendPrompt(input);
            }}
            className="flex items-center gap-2 pt-2 border-t border-[#27345C]/10"
          >
            <button
              type="button"
              onClick={toggleVoiceInput}
              disabled={!isEnabledForChild || loading}
              title={language === 'ar' ? 'تحدث بالميكروفون (بإذنك فقط)' : 'Optional Voice Input (on tap only)'}
              className={`min-h-[48px] min-w-[48px] rounded-2xl border-2 flex items-center justify-center cursor-pointer transition-colors disabled:opacity-45 ${
                micListening
                  ? 'bg-[#FF4D6D] text-white border-[#FF4D6D] animate-pulse'
                  : 'bg-[#FFF8E9] text-[#27345C] border-[#27345C]/15 hover:border-[#8054D9]'
              }`}
            >
              {micListening ? <Mic className="w-5 h-5" /> : <MicOff className="w-5 h-5 text-[#27345C]/65" />}
            </button>
            <input
              type="text"
              value={input}
              maxLength={320}
              disabled={!isEnabledForChild || loading}
              onChange={(e) => setInput(e.target.value)}
              placeholder={
                language === 'ar'
                  ? 'اكتب سؤالك التعليمي لنونو هنا...'
                  : 'Ask Nono a learning question here...'
              }
              className="flex-1 min-h-[48px] px-4 rounded-2xl border-2 border-[#27345C]/15 focus:border-[#8054D9] outline-none text-sm font-bold text-[#27345C]"
            />
            <button
              type="submit"
              disabled={!isEnabledForChild || loading || !input.trim()}
              className="min-h-[48px] px-5 rounded-2xl bg-[#8054D9] text-white font-extrabold text-sm flex items-center gap-2 cursor-pointer disabled:opacity-50"
            >
              <Send className="w-4 h-4" />
              <span>{loading ? (language === 'ar' ? 'يفكّر...' : 'Thinking...') : language === 'ar' ? 'إرسال' : 'Ask'}</span>
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
