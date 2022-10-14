import {
  ForbiddenException,
  Injectable,
} from '@nestjs/common';

import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable({})
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}
  async signup(dto: AuthDto) {
    try {
      // Generate password hash
      const hash = await argon.hash(dto.password);

      // create a new user
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      //  resturn token
      return this.signToken(user.id, user.email);
    } catch (error) {
      //    check if error is from prisma
      if (
        error instanceof
        PrismaClientKnownRequestError
      ) {
        if (error.code === 'P2002') {
          throw new ForbiddenException(
            'Credentials taken',
          );
        }
      }
      throw error;
    }
  }
  async signin(dto: AuthDto) {
    //   Find a user by email
    const user =
      await this.prisma.user.findUnique({
        where: {
          email: dto.email,
        },
      });

    //  check if user exit
    if (!user) {
      throw new ForbiddenException(
        'Credentials is incorrect',
      );
    }

    // compare password from the one in the db
    const pwMatches = await argon.verify(
      user.hash,
      dto.password,
    );
    // !possword throw exception
    if (!pwMatches) {
      throw new ForbiddenException(
        'Credentials is incorrect',
      );
    }

    // send back the user
    return this.signToken(user.id, user.email);
  }

  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };
    const secret = this.config.get('JWT_SECRET');

    const token = await this.jwt.signAsync(
      payload,
      {
        expiresIn: '15m',
        secret: secret,
      },
    );

    return {
      access_token: token,
    };
  }
}
