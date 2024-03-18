import bcrypt from "bcryptjs"
import NextAuth, { AuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials"
import GithubProvider from "next-auth/providers/github"
import GoogleProvider from "next-auth/providers/google"
import { PrismaAdapter } from "@next-auth/prisma-adapter"

import prisma from '@/libs/prismadb';

const login = async (credentials: any) => {
    try {
        const email = credentials?.email;
        const password = credentials?.password;

        if (!email || !password) {
            throw new Error('Invalid credentials');
        }

        const user = await prisma.user.findUnique({
            where: {
                email: credentials.email
            }
        });

        if (!user || !user?.hashedPassword) {
            throw new Error('Invalid credentials');
        }

        const isCorrectPassword = await bcrypt.compare(
            credentials.password,
            user.hashedPassword
        );

        if (!isCorrectPassword) {
            throw new Error('Invalid credentials');
        }

        return user;
    } catch (err) {
        console.error(err);
        throw new Error("Failed to login!");
    }
};

export const authOptions: AuthOptions = {
    adapter: PrismaAdapter(prisma),
    secret: process.env.NEXTAUTH_SECRET,
    providers: [
        GithubProvider({
            clientId: process.env.GITHUB_ID as string,
            clientSecret: process.env.GITHUB_SECRET as string
        }),
        GoogleProvider({
            clientId: process.env.GOOGLE_CLIENT_ID as string,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET as string
        }),
        CredentialsProvider({
            name: 'Credentials',
            id: 'credentials',
            credentials: {
                email: { label: 'email', type: 'email' },
                password: { label: 'password', type: 'password' }
            },
            async authorize(credentials) {
                try {
                    const user = await login(credentials);
                    return user;
                } catch (err) {
                    throw new Error('Something went wrong!');
                }
            }
        })
    ],
    pages: {
        signIn: '/',
    },
    debug: process.env.NODE_ENV === 'development',
    session: {
        strategy: "jwt",
    }
}

// export default NextAuth(authOptions);

const handler = NextAuth(authOptions);
export { handler as GET, handler as POST };