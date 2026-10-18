import { createContext, useContext } from 'react';

export const SessionCtx = createContext(null);
export const useSession = () => useContext(SessionCtx);
